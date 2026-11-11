"""
Vitorius Firewall - Service & Application Scanner
Automatically discovers network services, listening daemons, systemd units,
Flatpak apps, and desktop applications so users can enable or disable them.
"""

import os
import re
import glob
import json
import time
import socket
import logging
import getpass
import configparser
import subprocess
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field, asdict
from typing import Optional

logger = logging.getLogger('vitorius.scanner')


@dataclass
class ScannedItem:
    id: str                                     # Unique identifier, e.g. "svc:ssh" or "app:firefox"
    name: str                                   # Human readable name, e.g. "OpenSSH Server"
    category: str                               # "service" (system daemon / server) or "app" (desktop application)
    item_type: str                              # "firewalld_service", "systemd_service", "listening_daemon", "flatpak", "desktop_app", "process"
    icon: str                                   # GTK / FreeDesktop icon name
    description: str                            # Human friendly description
    service_name: str = ""                      # firewalld service name if applicable
    systemd_unit: str = ""                      # systemd unit name if applicable
    flatpak_id: str = ""                        # Flatpak App ID if applicable
    exec_name: str = ""                         # Binary name
    exec_path: str = ""                         # Full executable path
    ports: list[tuple[str, str]] = field(default_factory=list) # List of (port, protocol) tuples
    is_running: bool = False                    # True if currently running / listening
    pids: list[int] = field(default_factory=list) # Active PIDs
    is_enabled: bool = True                     # True if allowed through firewall, False if blocked
    details: dict = field(default_factory=dict) # Extra metadata

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict) -> 'ScannedItem':
        ports_raw = data.get('ports', [])
        ports = [tuple(p) if isinstance(p, (list, tuple)) else (str(p), 'tcp') for p in ports_raw]
        return cls(
            id=data.get('id', ''),
            name=data.get('name', ''),
            category=data.get('category', 'app'),
            item_type=data.get('item_type', 'desktop_app'),
            icon=data.get('icon', 'application-x-executable-symbolic'),
            description=data.get('description', ''),
            service_name=data.get('service_name', ''),
            systemd_unit=data.get('systemd_unit', ''),
            flatpak_id=data.get('flatpak_id', ''),
            exec_name=data.get('exec_name', ''),
            exec_path=data.get('exec_path', ''),
            ports=ports,
            is_running=data.get('is_running', False),
            pids=data.get('pids', []),
            is_enabled=data.get('is_enabled', True),
            details=data.get('details', {})
        )


# Mapping of popular service IDs to clean names, icons and fallback ports
WELL_KNOWN_SERVICES = {
    'ssh': {
        'name': 'OpenSSH Server (sshd)',
        'icon': 'utilities-terminal-symbolic',
        'desc': 'Secure remote shell login daemon',
        'ports': [('22', 'tcp')],
        'units': ['sshd.service', 'ssh.service'],
    },
    'samba': {
        'name': 'Samba File Sharing',
        'icon': 'folder-remote-symbolic',
        'desc': 'SMB/CIFS Windows network file and printer sharing',
        'ports': [('139', 'tcp'), ('445', 'tcp'), ('137', 'udp'), ('138', 'udp')],
        'units': ['smb.service', 'smbd.service', 'nmb.service'],
    },
    'cockpit': {
        'name': 'Cockpit Web Console',
        'icon': 'network-server-symbolic',
        'desc': 'Web-based Linux system administration interface',
        'ports': [('9090', 'tcp')],
        'units': ['cockpit.service', 'cockpit.socket', 'cockpit-ws.service'],
    },
    'syncthing': {
        'name': 'Syncthing File Synchronization',
        'icon': 'emblem-synchronizing-symbolic',
        'desc': 'Decentralized peer-to-peer continuous file synchronization',
        'ports': [('22000', 'tcp'), ('22000', 'udp'), ('21027', 'udp')],
        'units': ['syncthing@*.service', 'syncthing.service'],
    },
    'cups': {
        'name': 'CUPS Printing Server',
        'icon': 'printer-symbolic',
        'desc': 'Common Unix Printing System network print server',
        'ports': [('631', 'tcp'), ('631', 'udp')],
        'units': ['cups.service', 'cups.socket'],
    },
    'mdns': {
        'name': 'Avahi mDNS / Zeroconf',
        'icon': 'network-workgroup-symbolic',
        'desc': 'Multicast DNS local hostname and service discovery (.local)',
        'ports': [('5353', 'udp')],
        'units': ['avahi-daemon.service'],
    },
    'dns': {
        'name': 'DNS Server (BIND / Dnsmasq)',
        'icon': 'network-wired-symbolic',
        'desc': 'Inbound Domain Name System network server daemon',
        'ports': [('53', 'tcp'), ('53', 'udp')],
        'units': ['named.service', 'dnsmasq.service', 'bind9.service'],
    },
    'http': {
        'name': 'Web Server (HTTP)',
        'icon': 'web-browser-symbolic',
        'desc': 'Unencrypted Hypertext Transfer Protocol web server',
        'ports': [('80', 'tcp')],
        'units': ['nginx.service', 'httpd.service', 'apache2.service', 'caddy.service'],
    },
    'https': {
        'name': 'Secure Web Server (HTTPS)',
        'icon': 'security-high-symbolic',
        'desc': 'Encrypted TLS/SSL web server',
        'ports': [('443', 'tcp')],
        'units': ['nginx.service', 'httpd.service', 'apache2.service', 'caddy.service'],
    },
    'mysql': {
        'name': 'MySQL / MariaDB Database Server',
        'icon': 'network-server-symbolic',
        'desc': 'Relational SQL database network service',
        'ports': [('3306', 'tcp')],
        'units': ['mariadb.service', 'mysqld.service'],
    },
    'postgresql': {
        'name': 'PostgreSQL Database Server',
        'icon': 'network-server-symbolic',
        'desc': 'Enterprise relational database server',
        'ports': [('5432', 'tcp')],
        'units': ['postgresql.service'],
    },
    'libvirt': {
        'name': 'Libvirt Virtualization Daemon',
        'icon': 'computer-symbolic',
        'desc': 'QEMU/KVM virtual machine hypervisor management',
        'ports': [('16509', 'tcp')],
        'units': ['libvirtd.service', 'virtqemud.service'],
    },
    'wireguard': {
        'name': 'WireGuard VPN',
        'icon': 'network-vpn-symbolic',
        'desc': 'Modern high-speed encrypted VPN tunnel',
        'ports': [('51820', 'udp')],
        'units': ['wg-quick@*.service'],
    },
    'openvpn': {
        'name': 'OpenVPN Server',
        'icon': 'network-vpn-symbolic',
        'desc': 'SSL/TLS virtual private network tunnel',
        'ports': [('1194', 'udp')],
        'units': ['openvpn-server@*.service', 'openvpn@*.service'],
    },
    'kdeconnect': {
        'name': 'KDE Connect / GSConnect',
        'icon': 'phone-symbolic',
        'desc': 'Phone & PC wireless integration (clipboard, files, notifications)',
        'ports': [('1714-1764', 'tcp'), ('1714-1764', 'udp')],
        'units': [],
    },
    'plex': {
        'name': 'Plex Media Server',
        'icon': 'video-display-symbolic',
        'desc': 'Home media streaming and transcoding server',
        'ports': [('32400', 'tcp')],
        'units': ['plexmediaserver.service'],
    },
    'jellyfin': {
        'name': 'Jellyfin Media Server',
        'icon': 'video-display-symbolic',
        'desc': 'Open-source software media server for audio and video',
        'ports': [('8096', 'tcp')],
        'units': ['jellyfin.service'],
    },
    'vnc-server': {
        'name': 'VNC Remote Desktop Server',
        'icon': 'display-symbolic',
        'desc': 'Virtual Network Computing graphical remote control',
        'ports': [('5900', 'tcp')],
        'units': ['vncserver.service'],
    },
    'rdp': {
        'name': 'RDP Remote Desktop Server',
        'icon': 'display-symbolic',
        'desc': 'Remote Desktop Protocol service (xrdp / GNOME Remote Desktop)',
        'ports': [('3389', 'tcp')],
        'units': ['xrdp.service', 'gnome-remote-desktop.service'],
    },
}

# Icon heuristics based on app names or categories
APP_ICON_HEURISTICS = {
    'browser': 'web-browser-symbolic',
    'web': 'web-browser-symbolic',
    'firefox': 'web-browser-symbolic',
    'chrome': 'web-browser-symbolic',
    'brave': 'web-browser-symbolic',
    'game': 'input-gaming-symbolic',
    'steam': 'input-gaming-symbolic',
    'discord': 'user-available-symbolic',
    'chat': 'user-available-symbolic',
    'audio': 'audio-speakers-symbolic',
    'music': 'audio-speakers-symbolic',
    'spotify': 'audio-speakers-symbolic',
    'video': 'video-display-symbolic',
    'player': 'video-display-symbolic',
    'remote': 'folder-remote-symbolic',
    'terminal': 'utilities-terminal-symbolic',
    'code': 'text-x-generic-symbolic',
    'studio': 'applications-engineering-symbolic',
    'development': 'applications-engineering-symbolic',
}


class ServiceAppScanner:
    """
    Intelligent scanner that inventories all network-facing applications,
    system services, listening daemons, Flatpaks, and desktop entries.
    """

    def __init__(self):
        self._cached_items: list[ScannedItem] = []
        self._last_scan_time: float = 0.0
        self._is_scanning: bool = False
        self._fw_services_cache: dict = {}
        self._load_firewalld_service_definitions()

    def _load_firewalld_service_definitions(self):
        """Parse XML definitions in /usr/lib/firewalld/services and /etc/firewalld/services."""
        services = {}
        dirs = ['/usr/lib/firewalld/services', '/etc/firewalld/services']
        for d in dirs:
            if not os.path.isdir(d):
                continue
            for f in glob.glob(os.path.join(d, '*.xml')):
                try:
                    tree = ET.parse(f)
                    root = tree.getroot()
                    s_id = os.path.basename(f)[:-4].lower()
                    short = root.findtext('short') or s_id
                    desc = (root.findtext('description') or '').strip().split('\n')[0]
                    ports = []
                    for p in root.findall('port'):
                        port_num = p.get('port')
                        proto = p.get('protocol', 'tcp')
                        if port_num:
                            ports.append((port_num, proto))
                    services[s_id] = {
                        'id': s_id,
                        'name': short,
                        'desc': desc,
                        'ports': ports
                    }
                except Exception as e:
                    logger.debug(f"Error parsing service XML {f}: {e}")
        self._fw_services_cache = services

    def scan(self, firewall_core=None, profile_mgr=None, monitor=None) -> list[ScannedItem]:
        """
        Perform a comprehensive system scan across all sources:
        1. Firewalld and systemd services
        2. Listening sockets and daemons
        3. Flatpak applications
        4. Desktop application entries (.desktop)
        5. Active running network processes
        """
        self._is_scanning = True
        t0 = time.time()
        logger.info("Starting automatic service and application scan...")

        try:
            # 1. Systemd installed and active services
            systemd_units = self._scan_systemd_units()

            # 2. Listening sockets & processes
            listening_sockets = self._scan_listening_sockets()

            # 3. Flatpak applications
            flatpaks = self._scan_flatpaks()

            # 4. Desktop applications (.desktop files)
            desktop_apps = self._scan_desktop_apps()

            # 5. Running network processes from monitor
            running_procs = self._scan_running_processes(monitor)

            # 6. Current active firewall zone settings & blocked apps
            active_zone_services = set()
            active_zone_ports = set()
            blocked_apps = set()
            blocked_services = set()

            if firewall_core and hasattr(firewall_core, 'is_running') and firewall_core.is_running():
                try:
                    def_zone = firewall_core.get_default_zone()
                    settings = firewall_core.get_zone_settings(def_zone)
                    active_zone_services = set(s.lower() for s in settings.get('services', []))
                    for p in settings.get('ports', []):
                        active_zone_ports.add(f"{p['port']}/{p['protocol']}".lower())
                except Exception as e:
                    logger.debug(f"Error checking firewall settings during scan: {e}")

            if profile_mgr:
                blocked_apps = set(b.lower().strip() for b in profile_mgr.get_blocked_apps())
                blocked_services = set(b.lower().strip() for b in profile_mgr.get_setting('blocked_services', []))

            # Combine and build unified item catalog
            items: list[ScannedItem] = []
            seen_keys: set[str] = set()

            # ── A. Populate System Services & Daemons ─────────────────
            # Cross-reference firewalld services with installed systemd units and listening sockets
            for svc_id, svc_info in self._fw_services_cache.items():
                well_known = WELL_KNOWN_SERVICES.get(svc_id)
                
                # Check if this service is present or active on the machine
                unit_name = None
                is_unit_present = False
                is_unit_running = False

                possible_units = [f"{svc_id}.service", f"{svc_id}d.service"]
                if well_known and 'units' in well_known:
                    possible_units.extend(well_known['units'])

                for u_candidate in possible_units:
                    if '*' in u_candidate:
                        base = u_candidate.split('*')[0]
                        for u, u_info in systemd_units.items():
                            if u.startswith(base):
                                unit_name = u
                                is_unit_present = True
                                is_unit_running = (u_info.get('active_state') == 'active')
                                break
                    elif u_candidate in systemd_units:
                        unit_name = u_candidate
                        is_unit_present = True
                        is_unit_running = (systemd_units[u_candidate].get('active_state') == 'active')
                        break

                # Check if active in firewall zone
                is_fw_allowed = (svc_id in active_zone_services)

                # Check if any port is currently listening
                matching_listening = []
                svc_ports = svc_info.get('ports', [])
                if well_known and 'ports' in well_known:
                    svc_ports = list(set(svc_ports + well_known['ports']))

                for port_num, proto in svc_ports:
                    key = f"{port_num}/{proto}".lower()
                    if key in listening_sockets:
                        matching_listening.extend(listening_sockets[key])

                has_listeners = len(matching_listening) > 0
                active_pids = list({ls['pid'] for ls in matching_listening if ls.get('pid')})

                # Decide if this service should be included in the primary list
                # Include if: well-known service, OR installed systemd unit, OR active in firewall, OR has listening sockets
                if well_known or is_unit_present or is_fw_allowed or has_listeners:
                    display_name = well_known['name'] if well_known else svc_info['name']
                    icon = well_known['icon'] if well_known else 'network-server-symbolic'
                    description = well_known['desc'] if well_known else (svc_info['desc'] or f"Network service ({svc_id})")

                    ports_str = ", ".join([f"{p}/{pr}" for p, pr in svc_ports]) if svc_ports else "Dynamic"
                    if ports_str != "Dynamic":
                        desc_full = f"{description} • Ports: {ports_str}"
                    else:
                        desc_full = description

                    if unit_name:
                        desc_full += f" • {unit_name}"

                    is_running = is_unit_running or has_listeners

                    # Determine if blocked or allowed.
                    # Priority 1: explicitly in blocked_services / blocked_apps → disabled
                    # Priority 2: firewalld is running and zone has services listed → check membership
                    # Priority 3: firewalld not running or zone has no services listed → default enabled
                    is_enabled = True
                    if svc_id in blocked_services or svc_id in blocked_apps:
                        is_enabled = False
                    elif active_zone_services:
                        # Only mark as disabled if firewalld is active and this service
                        # is genuinely absent from the zone's allowed services list.
                        if svc_id not in active_zone_services:
                            is_enabled = False
                    # else: firewalld not running or zone empty → leave as True (don't alarm the user)

                    item_id = f"svc:{svc_id}"
                    item = ScannedItem(
                        id=item_id,
                        name=display_name,
                        category="service",
                        item_type="firewalld_service",
                        icon=icon,
                        description=desc_full,
                        service_name=svc_id,
                        systemd_unit=unit_name or "",
                        ports=svc_ports,
                        is_running=is_running,
                        pids=active_pids,
                        is_enabled=is_enabled,
                        details={'unit_present': is_unit_present, 'fw_allowed': is_fw_allowed}
                    )
                    items.append(item)
                    seen_keys.add(svc_id)
                    seen_keys.add(display_name.lower())

            # ── B. Populate Flatpak Applications ─────────────────────
            for fid, f_info in flatpaks.items():
                name = f_info.get('name', fid)
                norm_name = name.lower()
                icon = self._determine_app_icon(name, fid)
                desc = f"Flatpak Application • {fid}"

                # Check if running
                active_pids = []
                for p_name, p_data in running_procs.items():
                    if fid.lower() in p_name.lower() or norm_name in p_name.lower():
                        active_pids.extend(p_data.get('pids', []))

                is_running = len(active_pids) > 0
                is_blocked = (fid.lower() in blocked_apps or norm_name in blocked_apps or f_info.get('is_unshared', False))

                item_id = f"flatpak:{fid}"
                item = ScannedItem(
                    id=item_id,
                    name=name,
                    category="app",
                    item_type="flatpak",
                    icon=icon,
                    description=desc,
                    flatpak_id=fid,
                    exec_name=fid,
                    is_running=is_running,
                    pids=active_pids,
                    is_enabled=(not is_blocked),
                    details={'installation': f_info.get('installation', 'system')}
                )
                items.append(item)
                seen_keys.add(norm_name)
                seen_keys.add(fid.lower())

            # ── C. Populate Desktop Applications ─────────────────────
            for exe_name, d_info in desktop_apps.items():
                app_name = d_info.get('name', exe_name)
                norm_name = app_name.lower()
                if norm_name in seen_keys or exe_name.lower() in seen_keys:
                    continue

                icon = d_info.get('icon') or self._determine_app_icon(app_name, exe_name)
                comment = d_info.get('comment')
                desc = f"{comment} • {exe_name}" if comment else f"Desktop application • {exe_name}"

                # Check if running
                active_pids = []
                for p_name, p_data in running_procs.items():
                    if exe_name.lower() in p_name.lower() or norm_name in p_name.lower():
                        active_pids.extend(p_data.get('pids', []))

                is_running = len(active_pids) > 0
                is_blocked = (norm_name in blocked_apps or exe_name.lower() in blocked_apps)

                item_id = f"app:{exe_name.lower()}"
                item = ScannedItem(
                    id=item_id,
                    name=app_name,
                    category="app",
                    item_type="desktop_app",
                    icon=icon,
                    description=desc,
                    exec_name=exe_name,
                    exec_path=d_info.get('exec_path', ''),
                    is_running=is_running,
                    pids=active_pids,
                    is_enabled=(not is_blocked),
                    details={'categories': d_info.get('categories', '')}
                )
                items.append(item)
                seen_keys.add(norm_name)
                seen_keys.add(exe_name.lower())

            # ── D. Add Active Running Processes Not Yet Cataloged ────
            for prog, p_data in running_procs.items():
                norm_prog = prog.lower()
                if norm_prog in seen_keys or prog == "?" or not prog:
                    continue

                pids = p_data.get('pids', [])
                conns_count = p_data.get('connections_count', 0)
                icon = self._determine_app_icon(prog, prog)
                desc = f"Active running process • {conns_count} open socket{'s' if conns_count > 1 else ''}"

                is_blocked = (norm_prog in blocked_apps)
                item_id = f"proc:{norm_prog}"
                item = ScannedItem(
                    id=item_id,
                    name=prog.capitalize(),
                    category="app",
                    item_type="process",
                    icon=icon,
                    description=desc,
                    exec_name=prog,
                    is_running=True,
                    pids=pids,
                    is_enabled=(not is_blocked),
                )
                items.append(item)
                seen_keys.add(norm_prog)

            # ── E. Add Custom Apps Added by User in Settings ─────────
            if profile_mgr:
                for c_app in profile_mgr.get_custom_apps():
                    c_name = c_app.get('name', '').strip()
                    c_path = c_app.get('path', '').strip()
                    if c_name and c_name.lower() not in seen_keys:
                        is_blocked = (c_name.lower() in blocked_apps)
                        item = ScannedItem(
                            id=f"custom:{c_name.lower()}",
                            name=c_name,
                            category="app",
                            item_type="custom_app",
                            icon="application-x-executable-symbolic",
                            description=f"Custom application rule • {c_path}",
                            exec_name=c_name,
                            exec_path=c_path,
                            is_running=False,
                            is_enabled=(not is_blocked),
                            details={'custom': True}
                        )
                        items.append(item)
                        seen_keys.add(c_name.lower())

            # Sort items intelligently:
            # 1. Running / Listening items first
            # 2. Blocked items next (easy to find)
            # 3. Group by category (services first, then applications)
            # 4. Alphabetical by name
            def sort_key(it: ScannedItem):
                running_score = 0 if it.is_running else 1
                blocked_score = 0 if not it.is_enabled else 1
                cat_score = 0 if it.category == 'service' else 1
                return (running_score, blocked_score, cat_score, it.name.lower())

            items.sort(key=sort_key)

            self._cached_items = items
            self._last_scan_time = time.time()
            elapsed_ms = (self._last_scan_time - t0) * 1000
            logger.info(f"Scan completed in {elapsed_ms:.1f}ms: found {len(items)} items ({sum(1 for i in items if i.is_running)} active/listening, {sum(1 for i in items if not i.is_enabled)} blocked)")
            return items

        except Exception as e:
            logger.exception(f"Error during service & application scan: {e}")
            return self._cached_items
        finally:
            self._is_scanning = False

    def get_cached_items(self) -> list[ScannedItem]:
        return list(self._cached_items)

    def clear_cache(self):
        """Empty cached scanned items."""
        self._cached_items = []

    # ── Discovery Helpers ───────────────────────────────────────────

    def _scan_systemd_units(self) -> dict:
        """Scan systemd for installed and active services."""
        units = {}
        try:
            # Check unit files
            proc = subprocess.run(
                ['systemctl', 'list-unit-files', '--type=service', '--no-legend', '--no-pager'],
                capture_output=True, text=True, timeout=2.0
            )
            if proc.returncode == 0:
                for line in proc.stdout.splitlines():
                    parts = line.split()
                    if len(parts) >= 2:
                        u_name, state = parts[0], parts[1]
                        units[u_name] = {'unit': u_name, 'file_state': state, 'active_state': 'inactive'}

            # Check running units
            proc_running = subprocess.run(
                ['systemctl', 'list-units', '--type=service', '--state=running,active', '--no-legend', '--no-pager'],
                capture_output=True, text=True, timeout=2.0
            )
            if proc_running.returncode == 0:
                for line in proc_running.stdout.splitlines():
                    parts = line.split()
                    if parts:
                        u_name = parts[0]
                        if u_name in units:
                            units[u_name]['active_state'] = 'active'
                        else:
                            units[u_name] = {'unit': u_name, 'file_state': 'unknown', 'active_state': 'active'}
        except Exception as e:
            logger.debug(f"Error scanning systemd units: {e}")
        return units

    def _scan_listening_sockets(self) -> dict:
        """Find all ports currently listening and map them to their process."""
        listeners = {}
        try:
            import psutil
            for conn in psutil.net_connections(kind='inet'):
                if conn.status == 'LISTEN' and conn.laddr:
                    port = str(conn.laddr.port)
                    proto = 'tcp' if conn.type == socket.SOCK_STREAM else 'udp'
                    key = f"{port}/{proto}".lower()
                    proc_name = ""
                    if conn.pid:
                        try:
                            proc_name = psutil.Process(conn.pid).name()
                        except Exception:
                            pass
                    listeners[key] = listeners.get(key, [])
                    listeners[key].append({
                        'ip': conn.laddr.ip,
                        'port': port,
                        'proto': proto,
                        'pid': conn.pid or 0,
                        'program': proc_name
                    })
        except Exception:
            # Fallback: parse ss command
            try:
                proc = subprocess.run(
                    ['ss', '-H', '-t', '-u', '-l', '-p', '-n'],
                    capture_output=True, text=True, timeout=2.0
                )
                if proc.returncode == 0:
                    for line in proc.stdout.splitlines():
                        parts = line.split()
                        if len(parts) >= 4:
                            proto = parts[0].lower()
                            local = parts[3]
                            port = local.rsplit(':', 1)[-1] if ':' in local else ''
                            if port.isdigit():
                                key = f"{port}/{proto}".lower()
                                listeners[key] = [{'ip': local, 'port': port, 'proto': proto, 'pid': 0, 'program': ''}]
            except Exception:
                pass
        return listeners

    def _scan_flatpaks(self) -> dict:
        """Scan installed Flatpak applications and their network override status."""
        flatpaks = {}
        try:
            proc = subprocess.run(
                ['flatpak', 'list', '--app', '--columns=name,application,installation'],
                capture_output=True, text=True, timeout=2.5
            )
            if proc.returncode == 0:
                for line in proc.stdout.splitlines():
                    parts = line.strip().split('\t')
                    if len(parts) >= 2:
                        name = parts[0].strip()
                        app_id = parts[1].strip()
                        inst = parts[2].strip() if len(parts) >= 3 else 'system'
                        
                        # Check network unshared override
                        is_unshared = False
                        try:
                            check = subprocess.run(
                                ['flatpak', 'override', '--show', '--user', app_id],
                                capture_output=True, text=True, timeout=1.0
                            )
                            if check.returncode == 0 and 'unshare=network' in check.stdout:
                                is_unshared = True
                        except Exception:
                            pass

                        flatpaks[app_id] = {
                            'name': name,
                            'id': app_id,
                            'installation': inst,
                            'is_unshared': is_unshared
                        }
        except Exception as e:
            logger.debug(f"Error querying flatpak apps: {e}")
        return flatpaks

    def _scan_desktop_apps(self) -> dict:
        """Scan standard desktop entries for user applications."""
        apps = {}
        dirs = [
            '/usr/share/applications',
            '/usr/local/share/applications',
            os.path.expanduser('~/.local/share/applications'),
            '/var/lib/flatpak/exports/share/applications',
            os.path.expanduser('~/.local/share/flatpak/exports/share/applications')
        ]

        relevant_categories = {'network', 'game', 'audiovideo', 'development', 'office', 'utility', 'system', 'graphics'}

        for d in dirs:
            if not os.path.isdir(d):
                continue
            for f in glob.glob(os.path.join(d, '*.desktop')):
                try:
                    cp = configparser.ConfigParser(interpolation=None)
                    cp.read(f, encoding='utf-8')
                    if not cp.has_section('Desktop Entry'):
                        continue
                    e = cp['Desktop Entry']
                    if e.getboolean('NoDisplay', fallback=False):
                        continue
                    if e.get('Type') != 'Application':
                        continue

                    name = e.get('Name')
                    exec_line = e.get('Exec')
                    if not name or not exec_line:
                        continue

                    # Filter out helper launchers, settings, or desktop environment utilities
                    categories = e.get('Categories', '').lower()
                    cats_set = set(c.strip() for c in categories.split(';') if c.strip())
                    
                    # If categories specified, must touch at least one user category
                    if cats_set and not cats_set.intersection(relevant_categories):
                        continue

                    cmd_parts = exec_line.split()
                    exec_name = os.path.basename(cmd_parts[0]) if cmd_parts else ''
                    if not exec_name or exec_name.endswith('.sh') or exec_name in ('pkexec', 'sudo', 'gdm'):
                        continue

                    key = exec_name.lower()
                    if key not in apps:
                        apps[key] = {
                            'name': name,
                            'exec_name': exec_name,
                            'exec_path': cmd_parts[0],
                            'comment': e.get('Comment', ''),
                            'icon': e.get('Icon', 'application-x-executable-symbolic'),
                            'categories': categories,
                            'desktop_file': f
                        }
                except Exception:
                    pass
        return apps

    def _scan_running_processes(self, monitor) -> dict:
        """Extract active network processes and socket counts from NetworkMonitor."""
        procs = {}
        if not monitor:
            return procs

        try:
            conns = monitor.get_cached_connections()
            for c in conns:
                prog = c.program
                if prog and prog != '?':
                    if prog not in procs:
                        procs[prog] = {'connections_count': 0, 'pids': set()}
                    procs[prog]['connections_count'] += 1
                    if c.pid:
                        procs[prog]['pids'].add(c.pid)

            # Convert pids to list
            for prog in procs:
                procs[prog]['pids'] = list(procs[prog]['pids'])
        except Exception as e:
            logger.debug(f"Error gathering running processes: {e}")
        return procs

    def _determine_app_icon(self, name: str, exe: str) -> str:
        haystack = f"{name} {exe}".lower()
        for keyword, icon in APP_ICON_HEURISTICS.items():
            if keyword in haystack:
                return icon
        return 'application-x-executable-symbolic'

    # ── Enable / Disable (Allow / Block) Management ─────────────────

    def toggle_item(self, item: ScannedItem, allow: bool, firewall_core, profile_mgr) -> tuple[bool, str]:
        """
        Execute firewall and system operations to Enable (Allow) or Disable (Block)
        the specified service or application.
        """
        if item.category == 'service' or item.service_name:
            return self._toggle_service(item, allow, firewall_core, profile_mgr)
        else:
            return self._toggle_application(item, allow, firewall_core, profile_mgr)

    def _toggle_service(self, item: ScannedItem, allow: bool, firewall_core, profile_mgr) -> tuple[bool, str]:
        """Enable or disable a network service across active firewall zones and network layers."""
        svc = item.service_name or item.exec_name or item.id.replace('svc:', '')
        
        # Target all active zones and the default zone on Fedora
        zones_to_target = []
        if firewall_core:
            def_zone = firewall_core.get_default_zone() or 'public'
            zones_to_target.append(def_zone)
            active_dict = firewall_core.get_active_zones()
            for az in active_dict.keys():
                clean_az = az.split()[0].strip()
                if clean_az and clean_az not in zones_to_target:
                    zones_to_target.append(clean_az)
            if 'FedoraWorkstation' in firewall_core.get_zones() and 'FedoraWorkstation' not in zones_to_target:
                zones_to_target.append('FedoraWorkstation')
        if not zones_to_target:
            zones_to_target = ['public']

        commands = []
        is_protected_system_resolver = (
            svc.lower() in ('dns', 'systemd-resolved') or
            'resolved' in (item.systemd_unit or '').lower() or
            'networkmanager' in (item.systemd_unit or '').lower()
        )

        if allow:
            # 1. Enable service across all target zones in firewalld
            if svc:
                for z in zones_to_target:
                    commands.append(f'firewall-cmd --zone="{z}" --add-service="{svc}" 2>/dev/null || true')
                    commands.append(f'firewall-cmd --permanent --zone="{z}" --add-service="{svc}" 2>/dev/null || true')

            # 2. Remove port rejection rules, restore open ports, and clean leftover direct rules
            for port, proto in item.ports:
                for z in zones_to_target:
                    commands.append(f'firewall-cmd --zone="{z}" --remove-rich-rule=\'rule port port="{port}" protocol="{proto}" reject\' 2>/dev/null || true')
                    commands.append(f'firewall-cmd --permanent --zone="{z}" --remove-rich-rule=\'rule port port="{port}" protocol="{proto}" reject\' 2>/dev/null || true')
                    commands.append(f'firewall-cmd --zone="{z}" --add-port="{port}/{proto}" 2>/dev/null || true')
                    commands.append(f'firewall-cmd --permanent --zone="{z}" --add-port="{port}/{proto}" 2>/dev/null || true')
                # Clean up any leftover direct rules
                commands.append(f'firewall-cmd --direct --remove-rule ipv4 filter OUTPUT 0 -p {proto} --dport {port} -j REJECT 2>/dev/null || true')
                commands.append(f'firewall-cmd --direct --remove-rule ipv4 filter INPUT 0 -p {proto} --dport {port} -j REJECT 2>/dev/null || true')

            # 3. Unset systemd IPAddressDeny if unit exists
            if item.systemd_unit and not is_protected_system_resolver:
                unit = item.systemd_unit
                commands.append(f'systemctl set-property --runtime {unit} IPAddressAllow=any IPAddressDeny= 2>/dev/null || true')
                commands.append(f'systemctl --user set-property --runtime {unit} IPAddressAllow=any IPAddressDeny= 2>/dev/null || true')
                commands.append(f'systemctl restart {unit} 2>/dev/null || systemctl start {unit} 2>/dev/null || true')

            # 4. Clear cgroup iptables reject rules for active PIDs
            for pid in item.pids:
                try:
                    cg_file = f'/proc/{pid}/cgroup'
                    if os.path.exists(cg_file):
                        with open(cg_file, 'r') as f:
                            for line in f:
                                parts = line.strip().split(':')
                                if len(parts) >= 3:
                                    cg_path = parts[2].strip('/')
                                    if cg_path:
                                        commands.append(f'iptables -D OUTPUT -m cgroup --path "{cg_path}" -j REJECT 2>/dev/null || true')
                                        commands.append(f'iptables -D INPUT -m cgroup --path "{cg_path}" -j REJECT 2>/dev/null || true')
                except Exception:
                    pass

            # 5. Flush kernel routing & DNS caches so connections immediately work
            commands.append('resolvectl flush-caches 2>/dev/null || true')
            commands.append('ip route flush cache 2>/dev/null || true')
            commands.append('firewall-cmd --reload 2>/dev/null || true')

        else:
            # 1. Disable service across all target zones in firewalld
            if svc:
                for z in zones_to_target:
                    commands.append(f'firewall-cmd --zone="{z}" --remove-service="{svc}" 2>/dev/null || true')
                    commands.append(f'firewall-cmd --permanent --zone="{z}" --remove-service="{svc}" 2>/dev/null || true')

            # 2. Explicitly reject ports to ensure no incoming connections
            for port, proto in item.ports:
                for z in zones_to_target:
                    commands.append(f'firewall-cmd --zone="{z}" --remove-port="{port}/{proto}" 2>/dev/null || true')
                    commands.append(f'firewall-cmd --permanent --zone="{z}" --remove-port="{port}/{proto}" 2>/dev/null || true')
                    commands.append(f'firewall-cmd --zone="{z}" --add-rich-rule=\'rule port port="{port}" protocol="{proto}" reject\' 2>/dev/null || true')
                    commands.append(f'firewall-cmd --permanent --zone="{z}" --add-rich-rule=\'rule port port="{port}" protocol="{proto}" reject\' 2>/dev/null || true')
                commands.append(f'ss -K sport = :{port} 2>/dev/null || true')
                commands.append(f'ss -K dport = :{port} 2>/dev/null || true')

            # 3. Terminate active sockets and apply cgroup v2 reject for running PIDs
            for pid in item.pids:
                commands.append(f'ss -K pid = {pid} 2>/dev/null || true')
                try:
                    cg_file = f'/proc/{pid}/cgroup'
                    if os.path.exists(cg_file):
                        with open(cg_file, 'r') as f:
                            for line in f:
                                parts = line.strip().split(':')
                                if len(parts) >= 3:
                                    cg_path = parts[2].strip('/')
                                    if cg_path:
                                        commands.append(f'iptables -I OUTPUT 1 -m cgroup --path "{cg_path}" -j REJECT 2>/dev/null || true')
                                        commands.append(f'iptables -I INPUT 1 -m cgroup --path "{cg_path}" -j REJECT 2>/dev/null || true')
                except Exception:
                    pass

            # 4. Apply IPAddressDeny on unit if present (never on systemd-resolved)
            if item.systemd_unit and not is_protected_system_resolver:
                unit = item.systemd_unit
                commands.append(f'systemctl set-property --runtime {unit} IPAddressDeny=any 2>/dev/null || true')
                commands.append(f'systemctl --user set-property --runtime {unit} IPAddressDeny=any 2>/dev/null || true')
                commands.append(f'systemctl restart {unit} 2>/dev/null || true')

            commands.append('firewall-cmd --reload 2>/dev/null || true')

        success, msg = firewall_core.execute_batch(commands)
        if success:
            item.is_enabled = allow
            # Update settings
            if profile_mgr:
                blocked_services = set(profile_mgr.get_setting('blocked_services', []))
                if allow:
                    blocked_services.discard(svc)
                    profile_mgr.set_app_blocked(svc, False)
                else:
                    blocked_services.add(svc)
                    profile_mgr.set_app_blocked(svc, True, {'ports': item.ports, 'unit': item.systemd_unit})
                profile_mgr.update_settings({'blocked_services': sorted(list(blocked_services))})
            return True, f"Service '{item.name}' successfully {'enabled' if allow else 'disabled'}"
        return False, msg

    def _toggle_application(self, item: ScannedItem, allow: bool, firewall_core, profile_mgr) -> tuple[bool, str]:
        """Enable or disable a desktop or flatpak application."""
        app_name = item.name
        fid = item.flatpak_id
        pids = list(item.pids)
        ports = [int(p[0]) for p in item.ports if str(p[0]).isdigit()]

        if not allow:
            ok, msg = firewall_core.block_application(
                app_name=app_name,
                pids=pids,
                remote_ips=[],
                local_ports=ports
            )
            if ok:
                item.is_enabled = False
                if fid:
                    try:
                        subprocess.run(['flatpak', 'override', '--user', '--unshare=network', fid], capture_output=True, timeout=2.0)
                        subprocess.run(['flatpak', 'kill', fid], capture_output=True, timeout=2.0)
                    except Exception:
                        pass
                if profile_mgr:
                    profile_mgr.set_app_blocked(app_name, True, {'flatpak_id': fid, 'pids': pids, 'exec_name': item.exec_name})
                    if item.exec_name and item.exec_name.lower() != app_name.lower():
                        profile_mgr.set_app_blocked(item.exec_name, True)
                    if fid:
                        profile_mgr.set_app_blocked(fid, True)
                return True, f"Application '{app_name}' network access blocked"
            return False, msg
        else:
            ok, msg = firewall_core.unblock_application(
                app_name=app_name,
                pids=pids,
                remote_ips=[],
                local_ports=ports
            )
            if ok:
                item.is_enabled = True
                if fid:
                    try:
                        subprocess.run(['flatpak', 'override', '--user', '--share=network', fid], capture_output=True, timeout=2.0)
                        subprocess.run(['flatpak', 'override', '--user', '--reset', fid], capture_output=True, timeout=2.0)
                    except Exception:
                        pass
                if profile_mgr:
                    profile_mgr.set_app_blocked(app_name, False)
                    if item.exec_name:
                        profile_mgr.set_app_blocked(item.exec_name, False)
                    if fid:
                        profile_mgr.set_app_blocked(fid, False)
                return True, f"Application '{app_name}' network access restored"
            return False, msg
