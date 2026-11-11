"""
Vitorius Firewall - Application Pages
Implements DashboardPage, RulesPage, MonitorPage, AppsPage,
ProfilesPage, LogsPage, SettingsPage for GTK4/libadwaita.
"""

import gi
gi.require_version('Gtk', '4.0')
gi.require_version('Adw', '1')

from gi.repository import Gtk, Adw, Gio, GLib, Gdk, Pango
import os
import json
import logging
import threading
import shutil
import time
from pathlib import Path
from datetime import datetime

logger = logging.getLogger('vitorius.pages')



# =====================================================================
#  1. DASHBOARD PAGE
# =====================================================================

class DashboardPage(Gtk.ScrolledWindow):
    def __init__(self, main_win):
        super().__init__(vexpand=True, hexpand=True)
        self.win = main_win
        self.app = main_win.app

        clamp = Adw.Clamp(maximum_size=950, tightening_threshold=650)
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=20)
        box.set_margin_top(20)
        box.set_margin_bottom(30)
        box.set_margin_start(20)
        box.set_margin_end(20)
        clamp.set_child(box)
        self.set_child(clamp)

        # ── Banner Card ─────────────────────────────────────────────
        self.banner_group = Adw.PreferencesGroup()
        self.banner_card = Adw.ActionRow()
        self.banner_card.set_title("Corporate Protection Engine")
        self.banner_card.set_subtitle("Evaluating firewall and active network rules")
        self.status_icon = Gtk.Image.new_from_icon_name("security-high-symbolic")
        self.status_icon.set_pixel_size(32)
        self.banner_card.add_prefix(self.status_icon)

        self.btn_toggle_fw = Gtk.Button(label="Reload")
        self.btn_toggle_fw.set_valign(Gtk.Align.CENTER)
        self.btn_toggle_fw.connect("clicked", lambda b: self._reload_fw())
        self.banner_card.add_suffix(self.btn_toggle_fw)
        self.banner_group.add(self.banner_card)
        box.append(self.banner_group)

        # ── Statistics Grid ─────────────────────────────────────────
        stats_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=12)
        stats_box.set_homogeneous(True)

        self.card_active_zone = self._create_stat_card("Active Zone", "--", "network-workgroup-symbolic")
        self.card_profile = self._create_stat_card("Security Profile", "Standard", "emblem-system-symbolic")
        self.card_connections = self._create_stat_card("Live Conns", "0", "network-transmit-receive-symbolic")
        self.card_blocked = self._create_stat_card("Blocked IPs", "0", "action-unavailable-symbolic")

        stats_box.append(self.card_active_zone['box'])
        stats_box.append(self.card_profile['box'])
        stats_box.append(self.card_connections['box'])
        stats_box.append(self.card_blocked['box'])
        box.append(stats_box)

        # ── Quick Actions ───────────────────────────────────────────
        actions_group = Adw.PreferencesGroup(title="Quick Security Actions")
        actions_row = Adw.ActionRow(title="Firewall Controls", subtitle="Switch security posture or block an address")

        btn_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        btn_box.set_valign(Gtk.Align.CENTER)

        btn_block_ip = Gtk.Button(label="Quick Block IP")
        btn_block_ip.set_css_classes(["destructive-action"])
        btn_block_ip.connect("clicked", lambda b: self._dialog_block_ip())

        btn_rules = Gtk.Button(label="View Rules")
        btn_rules.connect("clicked", lambda b: self.win.navigate_to("rules"))

        btn_profile = Gtk.Button(label="Change Profile")
        btn_profile.set_css_classes(["suggested-action"])
        btn_profile.connect("clicked", lambda b: self.win.navigate_to("profiles"))

        btn_settings = Gtk.Button(label="Settings")
        btn_settings.connect("clicked", lambda b: self.win.navigate_to("settings"))

        btn_box.append(btn_block_ip)
        btn_box.append(btn_rules)
        btn_box.append(btn_profile)
        btn_box.append(btn_settings)
        actions_row.add_suffix(btn_box)
        actions_group.add(actions_row)

        # ── Scanned Services & Applications Row ─────────────────────
        self.services_row = Adw.ActionRow(
            title="Auto-Scanned Services &amp; Applications",
            subtitle="Evaluating background network daemons, system services, and desktop apps..."
        )
        self.services_icon = Gtk.Image.new_from_icon_name("application-x-executable-symbolic")
        self.services_icon.set_pixel_size(24)
        self.services_row.add_prefix(self.services_icon)

        btn_manage_apps = Gtk.Button(label="Manage Permissions")
        btn_manage_apps.set_valign(Gtk.Align.CENTER)
        btn_manage_apps.set_css_classes(["suggested-action"])
        btn_manage_apps.connect("clicked", lambda b: self.win.navigate_to("apps"))
        self.services_row.add_suffix(btn_manage_apps)
        actions_group.add(self.services_row)

        box.append(actions_group)

        # ── Bandwidth & Interfaces ──────────────────────────────────
        bw_group = Adw.PreferencesGroup(title="Network Interfaces &amp; Throughput")

        self.iface_listbox = Gtk.ListBox()
        self.iface_listbox.set_css_classes(["boxed-list"])
        bw_group.add(self.iface_listbox)
        box.append(bw_group)

        # ── Recent Security Events ──────────────────────────────────
        events_group = Adw.PreferencesGroup(title="Recent Audit Events")
        self.events_listbox = Gtk.ListBox()
        self.events_listbox.set_css_classes(["boxed-list"])
        events_group.add(self.events_listbox)
        box.append(events_group)

        self._iface_row_map = {}
        self._last_event_count = -1

        self.refresh()

    def _create_stat_card(self, title, initial_val, icon_name):
        card = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=6)
        card.set_css_classes(["stat-card"])

        top = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=6)
        icon = Gtk.Image.new_from_icon_name(icon_name)
        icon.set_pixel_size(16)
        lbl_title = Gtk.Label(label=title, xalign=0)
        lbl_title.set_css_classes(["stat-label"])
        top.append(icon)
        top.append(lbl_title)
        card.append(top)

        lbl_val = Gtk.Label(label=initial_val, xalign=0)
        lbl_val.set_css_classes(["stat-value"])
        card.append(lbl_val)

        return {'box': card, 'val': lbl_val}

    def _reload_fw(self):
        if self.app.core.get_panic_mode():
            self.win._prompt_unpanic()
        else:
            self.win._on_reload_clicked(None)

    def _dialog_block_ip(self):
        entry = Gtk.Entry(placeholder_text="e.g. 192.168.1.100 or 10.0.0.0/24")
        dialog = Adw.AlertDialog(
            heading="Quick Block IP Address",
            body="Enter an IP address or CIDR range to drop immediately:"
        )
        dialog.set_extra_child(entry)
        dialog.add_response("cancel", "Cancel")
        dialog.add_response("block", "Block IP")
        dialog.set_response_appearance("block", Adw.ResponseAppearance.DESTRUCTIVE)

        def on_resp(d, resp):
            if resp == "block":
                target = entry.get_text().strip()
                if target:
                    if self.app.core.block_ip(target):
                        self.app.fw_logger.log_event("ip_blocked", "warning", f"Blocked IP: {target}")
                        self.win._show_toast(f"IP {target} blocked")
                        self.refresh()
                    else:
                        self.win._show_toast(f"Failed to block {target} (check validity)")
        dialog.connect("response", on_resp)
        dialog.present(self.win)

    def refresh(self):
        # Update summary
        summary = self.app.core.get_summary()
        active_prof = self.app.profiles.get_active_profile()
        profile_display = active_prof if active_prof else "⚠ None Selected"

        self.card_active_zone['val'].set_label(summary.get('default_zone', 'public'))
        self.card_profile['val'].set_label(profile_display)
        self.card_blocked['val'].set_label(str(summary.get('blocked_ips', 0)))

        # Update banner
        if summary.get('panic_mode'):
            self.banner_card.set_title("⚠️ PANIC LOCKDOWN ACTIVE")
            self.banner_card.set_subtitle("All network traffic is currently severed")
            self.status_icon.set_from_icon_name("action-unavailable-symbolic")
            self.btn_toggle_fw.set_label("Restore Traffic")
            self.btn_toggle_fw.set_css_classes(["suggested-action"])
            self.btn_toggle_fw.set_tooltip_text("Lift panic lockdown and restore network traffic")
        elif summary.get('running'):
            if active_prof and active_prof != "⚠ None Selected":
                self.banner_card.set_title(f"Corporate Protection Active — {active_prof} Mode")
            else:
                self.banner_card.set_title("Firewall Active — No Security Profile Selected")
            self.banner_card.set_subtitle(f"Zone: {summary.get('default_zone')} • {summary.get('total_services')} services, {summary.get('total_ports')} ports open")
            self.status_icon.set_from_icon_name("security-high-symbolic")
            self.btn_toggle_fw.set_label("Reload")
            self.btn_toggle_fw.set_css_classes([])
            self.btn_toggle_fw.set_tooltip_text("Reload firewall configuration")
        else:
            self.banner_card.set_title("Firewall Inactive or Restricted")
            self.banner_card.set_subtitle("firewalld daemon is currently not running")
            self.status_icon.set_from_icon_name("dialog-warning-symbolic")
            self.btn_toggle_fw.set_label("Reload")
            self.btn_toggle_fw.set_css_classes([])
            self.btn_toggle_fw.set_tooltip_text("Reload firewall configuration")

        # Update stats
        stats = self.app.monitor.get_connection_stats()
        self.card_connections['val'].set_label(str(stats.get('total', 0)))

        # Update interfaces (in-place, no widget destruction)
        bw = self.app.monitor.get_bandwidth()
        ifaces = self.app.monitor.get_interfaces()
        
        current_iface_names = set(i.get('name') for i in ifaces)
        # Remove dead interfaces
        for name in list(self._iface_row_map.keys()):
            if name not in current_iface_names:
                row_info = self._iface_row_map.pop(name)
                self.iface_listbox.remove(row_info['row'])

        if not ifaces and not self._iface_row_map:
            if not getattr(self, '_empty_iface_row', None):
                self._empty_iface_row = Adw.ActionRow(title="No active physical network interfaces detected")
                self.iface_listbox.append(self._empty_iface_row)
        else:
            if getattr(self, '_empty_iface_row', None):
                self.iface_listbox.remove(self._empty_iface_row)
                self._empty_iface_row = None

            for iface in ifaces:
                name = iface.get('name')
                addrs = [a['address'] for a in iface.get('addresses', []) if a['type'] == 'IPv4']
                ip_str = ", ".join(addrs) if addrs else "No IPv4"
                
                rate_info = bw.get(name, {})
                rx = self.app.monitor.format_bytes(rate_info.get('rx_bytes_sec', 0))
                tx = self.app.monitor.format_bytes(rate_info.get('tx_bytes_sec', 0))
                sub_text = f"Speed: {iface.get('speed', 0)} Mb/s • State: {'UP' if iface.get('is_up') else 'DOWN'}"
                bw_text = f"↓ {rx}/s  ↑ {tx}/s"

                if name in self._iface_row_map:
                    # In-place update
                    row_info = self._iface_row_map[name]
                    row_info['row'].set_subtitle(sub_text)
                    row_info['bw_lbl'].set_label(bw_text)
                else:
                    # Create once
                    row = Adw.ActionRow()
                    row.set_title(f"{name} ({ip_str})")
                    row.set_subtitle(sub_text)

                    lbl_bw = Gtk.Label(label=bw_text)
                    lbl_bw.set_css_classes(["dim-label", "caption"])
                    row.add_suffix(lbl_bw)

                    self.iface_listbox.append(row)
                    self._iface_row_map[name] = {'row': row, 'bw_lbl': lbl_bw}

        # Update events only if new events arrived
        total_evs = self.app.fw_logger.get_stats().get('total_events', 0)
        if total_evs != self._last_event_count:
            self._last_event_count = total_evs
            while (row := self.events_listbox.get_first_child()) is not None:
                self.events_listbox.remove(row)

            events = self.app.fw_logger.get_events(count=5)
            if not events:
                row = Adw.ActionRow(title="No recent security alerts recorded")
                self.events_listbox.append(row)
            else:
                for e in reversed(events):
                    row = Adw.ActionRow()
                    sev = e.get('severity', 'info')
                    row.set_title(f"[{sev.upper()}] {e.get('type')}")
                    row.set_subtitle(f"{e.get('timestamp')[:19].replace('T', ' ')} — {e.get('details')}")
                    icon_map = {
                        'info': 'dialog-information-symbolic',
                        'warning': 'dialog-warning-symbolic',
                        'critical': 'dialog-error-symbolic',
                        'alert': 'security-low-symbolic',
                    }
                    img = Gtk.Image.new_from_icon_name(icon_map.get(sev, 'dialog-information-symbolic'))
                    row.add_prefix(img)
                    self.events_listbox.append(row)

    def update_scanner_summary(self, items):
        if not items or not hasattr(self, 'services_row'):
            return
        total = len(items)
        active = sum(1 for i in items if i.is_running)
        blocked = sum(1 for i in items if not i.is_enabled)
        svcs = sum(1 for i in items if i.category == 'service')
        self.services_row.set_subtitle(f"{total} cataloged ({svcs} services) • {active} active/listening • {blocked} blocked")



# =====================================================================
#  2. RULES PAGE
# =====================================================================

class RulesPage(Gtk.ScrolledWindow):
    def __init__(self, main_win):
        super().__init__(vexpand=True, hexpand=True)
        self.win = main_win
        self.app = main_win.app

        clamp = Adw.Clamp(maximum_size=950, tightening_threshold=650)
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=20)
        box.set_margin_top(20)
        box.set_margin_bottom(30)
        box.set_margin_start(20)
        box.set_margin_end(20)
        clamp.set_child(box)
        self.set_child(clamp)

        # Zone selector
        zone_group = Adw.PreferencesGroup(title="Active Zone Configuration")
        zone_row = Adw.ActionRow(title="Firewalld Zone", subtitle="Select network zone to inspect or modify rules")
        
        self.zone_combo = Gtk.DropDown()
        self.zone_combo.connect("notify::selected-item", lambda d, p: self._on_zone_changed())
        zone_row.add_suffix(self.zone_combo)
        zone_group.add(zone_row)
        box.append(zone_group)

        # Actions toolbar
        toolbar = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10)
        btn_add_port = Gtk.Button(label="+ Allow Port")
        btn_add_port.connect("clicked", lambda b: self._dialog_add_port())
        btn_add_svc = Gtk.Button(label="+ Allow Service")
        btn_add_svc.connect("clicked", lambda b: self._dialog_add_service())
        btn_block_ip = Gtk.Button(label="+ Block IP")
        btn_block_ip.set_css_classes(["destructive-action"])
        btn_block_ip.connect("clicked", lambda b: self._dialog_block_ip())
        btn_rich_rule = Gtk.Button(label="+ Custom Rich Rule")
        btn_rich_rule.connect("clicked", lambda b: self._dialog_add_rich_rule())

        toolbar.append(btn_add_port)
        toolbar.append(btn_add_svc)
        toolbar.append(btn_block_ip)
        toolbar.append(btn_rich_rule)
        box.append(toolbar)

        # Allowed Services List
        self.grp_services = Adw.PreferencesGroup(title="Allowed Services")
        self.list_services = Gtk.ListBox()
        self.list_services.set_css_classes(["boxed-list"])
        self.grp_services.add(self.list_services)
        box.append(self.grp_services)

        # Allowed Ports List
        self.grp_ports = Adw.PreferencesGroup(title="Allowed Ports")
        self.list_ports = Gtk.ListBox()
        self.list_ports.set_css_classes(["boxed-list"])
        self.grp_ports.add(self.list_ports)
        box.append(self.grp_ports)

        # Blocked IPs List
        self.grp_blocked = Adw.PreferencesGroup(title="Explicitly Blocked IPs &amp; Subnets")
        self.list_blocked = Gtk.ListBox()

        self.list_blocked.set_css_classes(["boxed-list"])
        self.grp_blocked.add(self.list_blocked)
        box.append(self.grp_blocked)

        # Rich Rules List
        self.grp_rich = Adw.PreferencesGroup(title="Advanced Rich Rules")
        self.list_rich = Gtk.ListBox()
        self.list_rich.set_css_classes(["boxed-list"])
        self.grp_rich.add(self.list_rich)
        box.append(self.grp_rich)

        self._populating_zones = False
        self.refresh()

    def _get_current_zone(self) -> str:
        selected_item = self.zone_combo.get_selected_item()
        if selected_item:
            return selected_item.get_string()
        return self.app.core.get_default_zone()

    def _on_zone_changed(self):
        if not self._populating_zones:
            current_zone = self._get_current_zone()
            self.app.profiles.update_settings({"last_rules_zone": current_zone})
            self._load_zone_rules(current_zone)

    def refresh(self):
        zones = self.app.core.get_zones()
        default_zone = self.app.core.get_default_zone()
        if not zones:
            zones = ["public", "home", "work", "drop", "trusted"]

        target_zone = self.app.profiles.get_setting("last_rules_zone", default_zone)
        if target_zone not in zones:
            target_zone = default_zone

        self._populating_zones = True
        str_list = Gtk.StringList.new(zones)
        self.zone_combo.set_model(str_list)

        try:
            idx = zones.index(target_zone)
            self.zone_combo.set_selected(idx)
        except ValueError:
            self.zone_combo.set_selected(0)
        self._populating_zones = False

        self._load_zone_rules(self._get_current_zone())

    def _load_zone_rules(self, zone: str):
        settings = self.app.core.get_zone_settings(zone)

        # 1. Services
        while (row := self.list_services.get_first_child()) is not None:
            self.list_services.remove(row)
        services = settings.get('services', [])
        if not services:
            self.list_services.append(Adw.ActionRow(title="No services permitted in this zone"))
        else:
            for svc in sorted(services):
                row = Adw.ActionRow(title=svc)
                del_btn = Gtk.Button(icon_name="user-trash-symbolic")
                del_btn.set_valign(Gtk.Align.CENTER)
                del_btn.connect("clicked", lambda b, s=svc: self._remove_service(zone, s))
                row.add_suffix(del_btn)
                self.list_services.append(row)

        # 2. Ports
        while (row := self.list_ports.get_first_child()) is not None:
            self.list_ports.remove(row)
        ports = settings.get('ports', [])
        if not ports:
            self.list_ports.append(Adw.ActionRow(title="No custom ports open"))
        else:
            for p in ports:
                port_str = f"{p['port']}/{p['protocol']}"
                row = Adw.ActionRow(title=port_str)
                del_btn = Gtk.Button(icon_name="user-trash-symbolic")
                del_btn.set_valign(Gtk.Align.CENTER)
                del_btn.connect("clicked", lambda b, pt=p['port'], pr=p['protocol']: self._remove_port(zone, pt, pr))
                row.add_suffix(del_btn)
                self.list_ports.append(row)

        # 3. Blocked IPs
        while (row := self.list_blocked.get_first_child()) is not None:
            self.list_blocked.remove(row)
        blocked_ips = self.app.core.get_blocked_ips(zone)
        if not blocked_ips:
            self.list_blocked.append(Adw.ActionRow(title="No addresses blocked in this zone"))
        else:
            for ip in blocked_ips:
                row = Adw.ActionRow(title=ip, subtitle="Traffic dropped/rejected")
                del_btn = Gtk.Button(icon_name="user-trash-symbolic")
                del_btn.set_valign(Gtk.Align.CENTER)
                del_btn.connect("clicked", lambda b, target_ip=ip: self._unblock_ip(zone, target_ip))
                row.add_suffix(del_btn)
                self.list_blocked.append(row)

        # 4. Rich Rules
        while (row := self.list_rich.get_first_child()) is not None:
            self.list_rich.remove(row)
        rich_rules = settings.get('rich_rules', [])
        if not rich_rules:
            self.list_rich.append(Adw.ActionRow(title="No advanced rich rules defined"))
        else:
            for rule in rich_rules:
                row = Adw.ActionRow(title=rule)
                del_btn = Gtk.Button(icon_name="user-trash-symbolic")
                del_btn.set_valign(Gtk.Align.CENTER)
                del_btn.connect("clicked", lambda b, r=rule: self._remove_rich_rule(zone, r))
                row.add_suffix(del_btn)
                self.list_rich.append(row)

    def _remove_service(self, zone, svc):
        def worker():
            ok = self.app.core.remove_service(zone, svc)
            def done():
                if ok:
                    self.app.fw_logger.log_event("rule_removed", "info", f"Removed service {svc} from {zone}")
                    self.win._show_toast(f"Removed service {svc}")
                    self._load_zone_rules(zone)
                else:
                    self.win._show_toast(f"Could not remove {svc} (cancelled or not allowed)")
            GLib.idle_add(done)
        threading.Thread(target=worker, daemon=True).start()

    def _remove_port(self, zone, port, proto):
        def worker():
            ok = self.app.core.remove_port(zone, port, proto)
            def done():
                if ok:
                    self.app.fw_logger.log_event("rule_removed", "info", f"Closed port {port}/{proto} on {zone}")
                    self.win._show_toast(f"Closed port {port}/{proto}")
                    self._load_zone_rules(zone)
                else:
                    self.win._show_toast(f"Could not close port {port}/{proto} (cancelled or not allowed)")
            GLib.idle_add(done)
        threading.Thread(target=worker, daemon=True).start()

    def _unblock_ip(self, zone, ip):
        def worker():
            ok = self.app.core.unblock_ip(ip, zone)
            def done():
                if ok:
                    self.app.fw_logger.log_event("ip_unblocked", "info", f"Unblocked IP {ip} in {zone}")
                    self.win._show_toast(f"Unblocked {ip}")
                    self._load_zone_rules(zone)
                else:
                    self.win._show_toast(f"Could not unblock {ip} (cancelled or not allowed)")
            GLib.idle_add(done)
        threading.Thread(target=worker, daemon=True).start()

    def _remove_rich_rule(self, zone, rule):
        def worker():
            ok = self.app.core.remove_rich_rule(zone, rule)
            def done():
                if ok:
                    self.app.fw_logger.log_event("rule_removed", "info", f"Removed rich rule from {zone}")
                    self.win._show_toast("Rule removed")
                    self._load_zone_rules(zone)
                else:
                    self.win._show_toast("Could not remove rule (cancelled or not allowed)")
            GLib.idle_add(done)
        threading.Thread(target=worker, daemon=True).start()

    def _dialog_add_port(self):
        zone = self._get_current_zone()
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=10)
        entry_port = Gtk.Entry(placeholder_text="Port (e.g. 8080 or 8000-8050)")
        proto_combo = Gtk.DropDown.new_from_strings(["tcp", "udp"])
        box.append(entry_port)
        box.append(proto_combo)

        dialog = Adw.AlertDialog(heading=f"Open Port on Zone '{zone}'")
        dialog.set_extra_child(box)
        dialog.add_response("cancel", "Cancel")
        dialog.add_response("add", "Open Port")
        dialog.set_response_appearance("add", Adw.ResponseAppearance.SUGGESTED)

        def on_resp(d, resp):
            if resp == "add":
                port = entry_port.get_text().strip()
                proto = proto_combo.get_selected_item().get_string()
                if port:
                    def worker():
                        ok = self.app.core.add_port(zone, port, proto)
                        def done():
                            if ok:
                                self.app.fw_logger.log_event("rule_added", "info", f"Opened port {port}/{proto} on {zone}")
                                self.win._show_toast(f"Port {port}/{proto} opened")
                                self._load_zone_rules(zone)
                            else:
                                self.win._show_toast("Failed to open port (cancelled or not allowed)")
                        GLib.idle_add(done)
                    threading.Thread(target=worker, daemon=True).start()
        dialog.connect("response", on_resp)
        dialog.present(self.win)

    def _dialog_add_service(self):
        zone = self._get_current_zone()
        avail = self.app.core.get_available_services()
        if not avail:
            avail = ["http", "https", "ssh", "samba", "dns", "nfs", "openvpn"]

        combo = Gtk.DropDown.new_from_strings(avail)
        dialog = Adw.AlertDialog(heading=f"Allow Service in Zone '{zone}'")
        dialog.set_extra_child(combo)
        dialog.add_response("cancel", "Cancel")
        dialog.add_response("add", "Allow Service")
        dialog.set_response_appearance("add", Adw.ResponseAppearance.SUGGESTED)

        def on_resp(d, resp):
            if resp == "add":
                svc = combo.get_selected_item().get_string()
                def worker():
                    ok = self.app.core.add_service(zone, svc)
                    def done():
                        if ok:
                            self.app.fw_logger.log_event("rule_added", "info", f"Allowed service {svc} in {zone}")
                            self.win._show_toast(f"Service {svc} allowed")
                            self._load_zone_rules(zone)
                        else:
                            self.win._show_toast("Failed to allow service (cancelled or not allowed)")
                    GLib.idle_add(done)
                threading.Thread(target=worker, daemon=True).start()
        dialog.connect("response", on_resp)
        dialog.present(self.win)

    def _dialog_block_ip(self):
        zone = self._get_current_zone()
        entry = Gtk.Entry(placeholder_text="e.g. 203.0.113.5 or 198.51.100.0/24")
        dialog = Adw.AlertDialog(heading=f"Block IP in Zone '{zone}'")
        dialog.set_extra_child(entry)
        dialog.add_response("cancel", "Cancel")
        dialog.add_response("block", "Block IP")
        dialog.set_response_appearance("block", Adw.ResponseAppearance.DESTRUCTIVE)

        def on_resp(d, resp):
            if resp == "block":
                ip = entry.get_text().strip()
                if ip:
                    def worker():
                        ok = self.app.core.block_ip(ip, zone)
                        def done():
                            if ok:
                                self.app.fw_logger.log_event("ip_blocked", "warning", f"Blocked IP {ip} in {zone}")
                                self.win._show_toast(f"Blocked {ip}")
                                self._load_zone_rules(zone)
                            else:
                                self.win._show_toast("Failed to block IP (cancelled or not allowed)")
                        GLib.idle_add(done)
                    threading.Thread(target=worker, daemon=True).start()
        dialog.connect("response", on_resp)
        dialog.present(self.win)

    def _dialog_add_rich_rule(self):
        zone = self._get_current_zone()
        entry = Gtk.Entry(placeholder_text='e.g. rule family="ipv4" source address="192.168.1.50" accept')
        dialog = Adw.AlertDialog(heading=f"Add Rich Rule to '{zone}'")
        dialog.set_extra_child(entry)
        dialog.add_response("cancel", "Cancel")
        dialog.add_response("add", "Add Rule")
        dialog.set_response_appearance("add", Adw.ResponseAppearance.SUGGESTED)

        def on_resp(d, resp):
            if resp == "add":
                rule = entry.get_text().strip()
                if rule:
                    def worker():
                        ok = self.app.core.add_rich_rule(zone, rule)
                        def done():
                            if ok:
                                self.app.fw_logger.log_event("rule_added", "info", f"Added rich rule to {zone}")
                                self.win._show_toast("Rich rule applied")
                                self._load_zone_rules(zone)
                            else:
                                self.win._show_toast("Failed to apply rich rule (cancelled or not allowed)")
                        GLib.idle_add(done)
                    threading.Thread(target=worker, daemon=True).start()
        dialog.connect("response", on_resp)
        dialog.present(self.win)


# =====================================================================
#  3. MONITOR PAGE
# =====================================================================

class MonitorPage(Gtk.Box):
    def __init__(self, main_win):
        super().__init__(orientation=Gtk.Orientation.VERTICAL, spacing=10)
        self.win = main_win
        self.app = main_win.app
        self.set_margin_top(12)
        self.set_margin_bottom(12)
        self.set_margin_start(16)
        self.set_margin_end(16)

        # Header bar with filters & search
        top_bar = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10)
        self.search_entry = Gtk.SearchEntry(placeholder_text="Filter by process, IP, port or protocol...")
        self.search_entry.set_hexpand(True)
        self._search_timeout = None
        self.search_entry.connect("search-changed", self._on_search_changed)
        top_bar.append(self.search_entry)

        self.proto_filter = Gtk.DropDown.new_from_strings(["All Protocols", "TCP", "UDP"])
        saved_proto = self.app.profiles.get_setting("monitor_proto_filter_idx", 0)
        self.proto_filter.set_selected(saved_proto if 0 <= saved_proto <= 2 else 0)
        self.proto_filter.connect("notify::selected-item", lambda d, p: self._on_filter_changed())
        top_bar.append(self.proto_filter)

        self.state_filter = Gtk.DropDown.new_from_strings(["All States", "ESTABLISHED", "LISTEN", "TIME_WAIT"])
        saved_state = self.app.profiles.get_setting("monitor_state_filter_idx", 0)
        self.state_filter.set_selected(saved_state if 0 <= saved_state <= 3 else 0)
        self.state_filter.connect("notify::selected-item", lambda d, p: self._on_filter_changed())
        top_bar.append(self.state_filter)

        btn_refresh = Gtk.Button(icon_name="view-refresh-symbolic")
        btn_refresh.connect("clicked", lambda b: self.refresh())
        top_bar.append(btn_refresh)
        self.append(top_bar)

        # Column titles
        headers = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10)
        headers.set_margin_start(16)
        headers.set_margin_end(16)
        headers.set_margin_top(6)
        headers.set_margin_bottom(6)
        headers.set_css_classes(["dim-label", "caption"])

        lbl_proto = Gtk.Label(label="Proto", width_chars=6, xalign=0)
        lbl_prog = Gtk.Label(label="Program / PID", width_chars=22, xalign=0)
        lbl_local = Gtk.Label(label="Local Address:Port", width_chars=26, xalign=0)
        lbl_remote = Gtk.Label(label="Remote Address:Port", width_chars=26, xalign=0)
        lbl_state = Gtk.Label(label="State", width_chars=14, xalign=0)
        lbl_act = Gtk.Label(label="Action", width_chars=8, xalign=1)

        headers.append(lbl_proto)
        headers.append(lbl_prog)
        headers.append(lbl_local)
        headers.append(lbl_remote)
        headers.append(lbl_state)
        headers.append(lbl_act)
        self.append(headers)

        # Connection List
        scroll = Gtk.ScrolledWindow(vexpand=True)
        self.conn_list = Gtk.ListBox()
        self.conn_list.set_css_classes(["boxed-list"])
        scroll.set_child(self.conn_list)
        self.append(scroll)

        # Status summary bar
        self.lbl_stats = Gtk.Label(label="Loading network statistics...")
        self.lbl_stats.set_css_classes(["dim-label", "caption"])
        self.lbl_stats.set_xalign(0)
        self.append(self.lbl_stats)

        self.refresh()

    def _on_search_changed(self, entry):
        if self._search_timeout:
            GLib.source_remove(self._search_timeout)
        self._search_timeout = GLib.timeout_add(250, self._do_search_refresh)

    def _do_search_refresh(self):
        self._search_timeout = None
        self.refresh()
        return False

    def _on_filter_changed(self):
        try:
            self.app.profiles.update_settings({
                "monitor_proto_filter_idx": self.proto_filter.get_selected(),
                "monitor_state_filter_idx": self.state_filter.get_selected(),
            })
        except Exception:
            pass
        self.refresh()

    def refresh(self):
        query = self.search_entry.get_text().strip().lower()
        proto_sel = self.proto_filter.get_selected_item().get_string()
        state_sel = self.state_filter.get_selected_item().get_string()

        # Read pre-computed background snapshot (0ms latency, zero syscalls)
        conns = self.app.monitor.get_cached_connections()
        if not conns:
            conns = self.app.monitor.get_connections_psutil()

        # Clear list
        while (row := self.conn_list.get_first_child()) is not None:
            self.conn_list.remove(row)

        matched_count = 0
        for c in conns:
            if proto_sel != "All Protocols" and c.protocol != proto_sel:
                continue
            if state_sel != "All States" and c.state != state_sel:
                continue

            prog_str = f"{c.program or 'Unknown'} ({c.pid or '?'})"
            local_str = f"{c.local_ip}:{c.local_port}"
            remote_str = f"{c.remote_ip}:{c.remote_port}" if c.remote_ip != "0.0.0.0" else "—"

            # Search text match
            haystack = f"{c.protocol} {prog_str} {local_str} {remote_str} {c.state} {c.service}".lower()
            if query and query not in haystack:
                continue

            matched_count += 1
            if matched_count > 50:  # Cap rendered rows to 50 for silky 60fps scrolling
                continue

            row = Gtk.ListBoxRow()
            h_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10)
            h_box.set_margin_top(4)
            h_box.set_margin_bottom(4)
            h_box.set_margin_start(16)
            h_box.set_margin_end(16)

            p_lbl = Gtk.Label(label=c.protocol, width_chars=6, xalign=0)
            prg_lbl = Gtk.Label(label=prog_str, width_chars=22, xalign=0, ellipsize=Pango.EllipsizeMode.END)
            loc_lbl = Gtk.Label(label=local_str, width_chars=26, xalign=0, ellipsize=Pango.EllipsizeMode.MIDDLE)
            rem_lbl = Gtk.Label(label=remote_str, width_chars=26, xalign=0, ellipsize=Pango.EllipsizeMode.MIDDLE)

            st_lbl = Gtk.Label(label=c.state, width_chars=14, xalign=0)
            if c.state == 'ESTABLISHED':
                st_lbl.set_css_classes(["conn-established"])
            elif c.state == 'LISTEN':
                st_lbl.set_css_classes(["conn-listen"])

            h_box.append(p_lbl)
            h_box.append(prg_lbl)
            h_box.append(loc_lbl)
            h_box.append(rem_lbl)
            h_box.append(st_lbl)

            if c.remote_ip and c.remote_ip not in ("0.0.0.0", "127.0.0.1", "::1"):
                btn_block = Gtk.Button(label="Block")
                btn_block.set_css_classes(["destructive-action"])
                btn_block.connect("clicked", lambda b, rip=c.remote_ip: self._quick_block(rip))
                h_box.append(btn_block)
            else:
                spacer = Gtk.Box(width_request=50)
                h_box.append(spacer)

            row.set_child(h_box)
            self.conn_list.append(row)

        stats = self.app.monitor.get_connection_stats()
        self.lbl_stats.set_label(
            f"Active: {stats.get('total', 0)} total | Established: {stats.get('established', 0)} | "
            f"Listening: {stats.get('listening', 0)} | Unique Remote Hosts: {stats.get('unique_remote_ips', 0)} "
            f"(Showing {min(matched_count, 50)} of {matched_count} matches)"
        )


    def _quick_block(self, ip: str):
        if self.app.core.block_ip(ip):
            self.app.fw_logger.log_event("ip_blocked", "alert", f"Blocked remote connection IP: {ip}")
            self.win._show_toast(f"Blocked IP {ip}")
            self.refresh()
        else:
            self.win._show_toast(f"Failed to block {ip}")


# =====================================================================
#  4. SERVICES & APPLICATIONS CONTROL PAGE (Windows-Style Management)
# =====================================================================

class AppsPage(Gtk.ScrolledWindow):
    def __init__(self, main_win):
        super().__init__(vexpand=True, hexpand=True)
        self.win = main_win
        self.app = main_win.app
        self._scanned_items = []
        self._refreshing = False
        self._toggling_ids = set()

        clamp = Adw.Clamp(maximum_size=950, tightening_threshold=650)
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=20)
        box.set_margin_top(20)
        box.set_margin_bottom(30)
        box.set_margin_start(20)
        box.set_margin_end(20)
        clamp.set_child(box)
        self.set_child(clamp)

        # ── Banner Card ─────────────────────────────────────────────
        self.banner_group = Adw.PreferencesGroup()
        self.banner_card = Adw.ActionRow(
            title="Auto-Scanned Services &amp; Applications",
            subtitle="Evaluating background network daemons, system services, and desktop apps..."
        )
        self.status_icon = Gtk.Image.new_from_icon_name("security-high-symbolic")
        self.status_icon.set_pixel_size(32)
        self.banner_card.add_prefix(self.status_icon)

        banner_actions = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        banner_actions.set_valign(Gtk.Align.CENTER)

        self.scan_spinner = Gtk.Spinner()
        banner_actions.append(self.scan_spinner)

        self.btn_rescan = Gtk.Button(label="Rescan", icon_name="view-refresh-symbolic")
        self.btn_rescan.set_tooltip_text("Rescan all services and applications now")
        self.btn_rescan.connect("clicked", lambda b: self._on_rescan_clicked())
        banner_actions.append(self.btn_rescan)

        self.banner_card.add_suffix(banner_actions)
        self.banner_group.add(self.banner_card)
        box.append(self.banner_group)

        # ── Toolbar: Search & Category Filter ───────────────────────
        tool_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10)

        self.search_app = Gtk.SearchEntry(placeholder_text="Search services, applications, ports (e.g. ssh, 22, brave)...")
        self.search_app.set_hexpand(True)
        self.search_app.connect("search-changed", lambda e: self.refresh())
        tool_box.append(self.search_app)

        self.cat_filter = Gtk.DropDown.new_from_strings([
            "All Items",
            "Services & Daemons",
            "Desktop Applications",
            "Listening / Active",
            "Blocked Only"
        ])
        self.cat_filter.connect("notify::selected-item", lambda d, p: self.refresh())
        tool_box.append(self.cat_filter)

        btn_add = Gtk.Button(label="+ Add Custom Rule")
        btn_add.connect("clicked", lambda b: self._dialog_add_app())
        tool_box.append(btn_add)
        box.append(tool_box)

        # ── Catalog List ────────────────────────────────────────────
        self.grp_apps = Adw.PreferencesGroup(title="Services &amp; Applications Catalog")
        self.list_apps = Gtk.ListBox()
        self.list_apps.set_css_classes(["boxed-list"])
        self.grp_apps.add(self.list_apps)
        box.append(self.grp_apps)

        # Initial populate from cached scanner items if already scanned
        if hasattr(self.win, 'scanner'):
            cached = self.win.scanner.get_cached_items()
            if cached:
                self.set_scanned_items(cached)
            else:
                self.refresh()
        else:
            self.refresh()

    def set_scanned_items(self, items):
        """Update scanned items from background scanner."""
        self._scanned_items = list(items)
        total = len(items)
        active = sum(1 for i in items if i.is_running)
        blocked = sum(1 for i in items if not i.is_enabled)
        svcs = sum(1 for i in items if i.category == 'service')
        apps = total - svcs

        self.banner_card.set_title(f"Auto-Scan Status: {total} Items Discovered")
        self.banner_card.set_subtitle(
            f"{svcs} Services & Daemons • {apps} Desktop Apps • {active} Active/Listening • {blocked} Blocked"
        )
        self.scan_spinner.stop()
        self.refresh()

    def _on_rescan_clicked(self):
        self.scan_spinner.start()
        self.banner_card.set_subtitle("Scanning system services, listening ports, Flatpaks, and applications...")
        self.win.trigger_service_scan(on_finish=lambda items: self.scan_spinner.stop())

    def refresh(self):
        """Filter and render items in the list box."""
        self._refreshing = True
        try:
            while (row := self.list_apps.get_first_child()) is not None:
                self.list_apps.remove(row)

            # If no items scanned yet, attempt to pull from scanner cache
            items = self._scanned_items
            if not items and hasattr(self.win, 'scanner'):
                items = self.win.scanner.get_cached_items()
                if items:
                    self._scanned_items = list(items)

            query = self.search_app.get_text().strip().lower()
            cat_idx = self.cat_filter.get_selected()

            matched_items = []
            for item in items:
                # Category Filter
                # 0: All, 1: Services, 2: Apps, 3: Active, 4: Blocked
                if cat_idx == 1 and item.category != 'service':
                    continue
                elif cat_idx == 2 and item.category != 'app':
                    continue
                elif cat_idx == 3 and not item.is_running:
                    continue
                elif cat_idx == 4 and item.is_enabled:
                    continue

                # Search Filter
                if query:
                    ports_str = " ".join([f"{p[0]}/{p[1]}" for p in item.ports]) if item.ports else ""
                    haystack = f"{item.name} {item.description} {item.exec_name} {item.service_name} {item.flatpak_id} {ports_str} {item.category}".lower()
                    if query not in haystack:
                        continue

                matched_items.append(item)

            if not matched_items:
                empty_title = "No services or applications match current filter"
                if not items:
                    empty_title = "Scanning services &amp; applications... (click Rescan if needed)"
                row = Adw.ActionRow(title=empty_title)
                self.list_apps.append(row)
                return

            for item in matched_items:
                row = Adw.ActionRow()

                # Prefix icon
                img = Gtk.Image.new_from_icon_name(item.icon)
                img.set_pixel_size(26)
                row.add_prefix(img)

                # Title with tags
                tags = []
                if item.category == 'service':
                    tags.append("<span size='smaller' alpha='70%'>[SERVICE]</span>")
                elif item.item_type == 'flatpak':
                    tags.append("<span size='smaller' alpha='70%'>[FLATPAK]</span>")
                else:
                    tags.append("<span size='smaller' alpha='70%'>[APP]</span>")

                if item.is_running:
                    if item.category == 'service' and item.ports:
                        p_str = ", ".join([f"{p[0]}/{p[1]}" for p in item.ports[:2]])
                        tags.append(f"<span foreground='#2ec27e' size='smaller'>● LISTENING ({p_str})</span>")
                    else:
                        tags.append("<span foreground='#2ec27e' size='smaller'>● ACTIVE</span>")

                title_markup = f"<b>{GLib.markup_escape_text(item.name)}</b> {' '.join(tags)}"
                row.set_title(title_markup)

                # Subtitle
                sub_text = item.description
                if not item.is_enabled:
                    sub_text = f"{sub_text}\n<span foreground='#e01b24'><b>[BLOCKED]</b> Network Traffic Dropped/Severed</span>"
                row.set_subtitle(sub_text)

                # Custom app trash button
                if item.details.get('custom'):
                    btn_del = Gtk.Button(icon_name="user-trash-symbolic")
                    btn_del.set_valign(Gtk.Align.CENTER)
                    btn_del.set_has_frame(False)
                    btn_del.set_tooltip_text("Remove custom rule")
                    btn_del.connect("clicked", lambda b, it=item: self._remove_custom_app(it))
                    row.add_suffix(btn_del)

                # Switch
                sw = Gtk.Switch()
                sw.set_valign(Gtk.Align.CENTER)
                sw.set_active(item.is_enabled)
                sw.set_tooltip_text("Allow (ON) or Block (OFF) network access")
                sw.connect("state-set", lambda s, st, it=item: self._toggle_item(it, s, st))
                row.add_suffix(sw)

                self.list_apps.append(row)

        finally:
            self._refreshing = False

    def _toggle_item(self, item, switch, allow: bool):
        if getattr(self, '_refreshing', False):
            return False

        if item.id in self._toggling_ids:
            return True
        self._toggling_ids.add(item.id)

        action_name = "Allow" if allow else "Block"
        self.win._show_toast(f"{action_name}ing '{item.name}'...")

        def worker():
            ok, msg = self.win.scanner.toggle_item(
                item=item,
                allow=allow,
                firewall_core=self.app.core,
                profile_mgr=self.app.profiles
            )
            def done():
                self._toggling_ids.discard(item.id)
                if ok:
                    item.is_enabled = allow
                    self.app.fw_logger.log_event(
                        "config_changed",
                        "info" if allow else "warning",
                        f"Firewall policy: {item.name} -> {'Allowed' if allow else 'Blocked'}"
                    )
                    self.win._show_toast(f"'{item.name}': Network access {'restored' if allow else 'blocked'}")
                    # Update banner subtitle counts
                    total = len(self._scanned_items)
                    active = sum(1 for i in self._scanned_items if i.is_running)
                    blocked = sum(1 for i in self._scanned_items if not i.is_enabled)
                    svcs = sum(1 for i in self._scanned_items if i.category == 'service')
                    apps = total - svcs
                    self.banner_card.set_subtitle(
                        f"{svcs} Services & Daemons • {apps} Desktop Apps • {active} Active/Listening • {blocked} Blocked"
                    )
                    self.refresh()
                else:
                    # Roll back switch state without re-triggering
                    self._refreshing = True
                    try:
                        switch.set_active(item.is_enabled)
                    finally:
                        self._refreshing = False
                    self.win._show_toast(f"'{item.name}': Authorization cancelled or failed")
            GLib.idle_add(done)

        threading.Thread(target=worker, daemon=True, name=f"toggle-{item.id}").start()
        return False

    def _remove_custom_app(self, item):
        self.app.profiles.remove_custom_app(item.name)
        self._scanned_items = [i for i in self._scanned_items if i.id != item.id]
        if not item.is_enabled:
            self._toggle_item(item, None, True)
        self.refresh()

    def _dialog_add_app(self):
        entry_name = Gtk.Entry(placeholder_text="Application / Service name (e.g. Custom Web Server)")
        entry_path = Gtk.Entry(placeholder_text="Binary name, command, or Flatpak ID (e.g. my-server or com.app)")
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=10)
        box.append(entry_name)
        box.append(entry_path)

        dialog = Adw.AlertDialog(heading="Add Custom Application / Service Rule")
        dialog.set_extra_child(box)
        dialog.add_response("cancel", "Cancel")
        dialog.add_response("add", "Add Rule")
        dialog.set_response_appearance("add", Adw.ResponseAppearance.SUGGESTED)

        def on_resp(d, resp):
            if resp == "add":
                name = entry_name.get_text().strip()
                path = entry_path.get_text().strip()
                if name:
                    self.app.profiles.add_custom_app(name, path)
                    self.app.fw_logger.log_event("rule_added", "info", f"Custom application added: {name}")
                    self.win._show_toast(f"Added custom rule: {name}")
                    self.win.trigger_service_scan()
        dialog.connect("response", on_resp)
        dialog.present(self.win)


# =====================================================================
#  5. SECURITY PROFILES PAGE (Standard vs Premium / Corporate)
# =====================================================================

class ProfilesPage(Gtk.ScrolledWindow):
    def __init__(self, main_win):
        super().__init__(vexpand=True, hexpand=True)
        self.win = main_win
        self.app = main_win.app

        clamp = Adw.Clamp(maximum_size=950, tightening_threshold=650)
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=20)
        box.set_margin_top(20)
        box.set_margin_bottom(30)
        box.set_margin_start(20)
        box.set_margin_end(20)
        clamp.set_child(box)
        self.set_child(clamp)

        # Header
        grp_head = Adw.PreferencesGroup(
            title="Enterprise Security Profiles",
            description="Choose a security tier to enforce a predefined firewall policy. "
                        "On a fresh install, no profile is active — select one to get started. "
                        "Switching profiles applies a full clean-slate firewall configuration."
        )
        box.append(grp_head)

        # Backup & Restore toolbar
        bar = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10)
        btn_backup = Gtk.Button(label="Backup Current Rules")
        btn_backup.connect("clicked", lambda b: self._backup_rules())
        btn_restore = Gtk.Button(label="Restore Backup")
        btn_restore.connect("clicked", lambda b: self._restore_rules())
        bar.append(btn_backup)
        bar.append(btn_restore)
        box.append(bar)

        # Profile Cards Container
        self.grp_profiles = Adw.PreferencesGroup(title="Available Security Tiers")
        self.list_profiles = Gtk.ListBox()
        self.list_profiles.set_css_classes(["boxed-list"])
        self.grp_profiles.add(self.list_profiles)
        box.append(self.grp_profiles)

        self.refresh()

    def refresh(self):
        while (row := self.list_profiles.get_first_child()) is not None:
            self.list_profiles.remove(row)

        profiles = self.app.profiles.get_profiles()
        active = self.app.profiles.get_active_profile()

        # ── Fresh-install / No Profile banner ───────────────────────
        if not active:
            banner_row = Adw.ActionRow(
                title="No Security Profile Active",
                subtitle="Your firewall is running on its current system configuration. "
                         "Choose a profile below to enforce a predefined security policy.",
            )
            banner_row.set_css_classes(["warning"])
            lbl_warn = Gtk.Label(label="⚠ No Profile")
            lbl_warn.set_css_classes(["warning"])
            banner_row.add_suffix(lbl_warn)
            self.list_profiles.append(banner_row)

        for name, data in profiles.items():
            row = Adw.ActionRow()
            tier = data.get('tier', 'standard').upper()
            icon = data.get('icon', 'security-medium-symbolic')

            img = Gtk.Image.new_from_icon_name(icon)
            img.set_pixel_size(28)
            row.add_prefix(img)

            title_str = f"{name}  ({tier})"
            if active == name:
                title_str += "  ✓ ACTIVE"
            row.set_title(title_str)

            features = []
            if data.get('compliance'):
                features.append(f"Compliance: {data.get('compliance')}")
            if data.get('ids_enabled'):
                features.append("IDS Heuristics")
            if data.get('geo_blocking'):
                features.append(f"Geo-Block ({len(data.get('blocked_countries', []))} regions)")
            if data.get('rate_limit'):
                features.append("Rate Limiting")
            if data.get('icmp_block_inversion'):
                features.append("ICMP Inversion")
            feat_str = f" • Features: {', '.join(features)}" if features else ""

            # Build a richer subtitle with zone, logging level and services summary
            zone_str = data.get('default_zone', '—')
            log_str = data.get('logging', 'minimal').capitalize()
            svcs = data.get('allowed_services', [])
            svcs_str = ", ".join(svcs[:4]) + (" +" + str(len(svcs) - 4) + " more" if len(svcs) > 4 else "") if svcs else "None"
            ports_count = len(data.get('allowed_ports', []))
            row.set_subtitle(
                f"{data.get('description', '')}{feat_str}\n"
                f"Zone: {zone_str} • Logging: {log_str} • "
                f"Services: {svcs_str} • Open Ports: {ports_count}"
            )

            # Apply button
            btn_apply = Gtk.Button(label="Activate")
            if active == name:
                btn_apply.set_sensitive(False)
                btn_apply.set_label("Current")
            else:
                btn_apply.set_css_classes(["suggested-action"])
                btn_apply.connect("clicked", lambda b, pname=name: self._apply_profile(pname))

            btn_apply.set_valign(Gtk.Align.CENTER)
            row.add_suffix(btn_apply)
            self.list_profiles.append(row)

    def _apply_profile(self, name: str):
        self.win._show_toast(f"Activating profile '{name}'...")

        def worker():
            success, msg = self.app.profiles.apply_profile(name, self.app.core)
            def done():
                if success:
                    self.app.fw_logger.log_event("profile_changed", "info", f"Switched profile to: {name}")
                    self.win._show_toast(f"Profile '{name}' activated successfully")
                    self.refresh()
                    self.win._update_status()
                else:
                    self.win._show_toast(f"Profile change: {msg}")
            GLib.idle_add(done)

        threading.Thread(target=worker, daemon=True, name=f"apply-profile-{name}").start()

    def _backup_rules(self):
        backup_path = self.app.profiles.backup_rules(self.app.core)
        if backup_path:
            filename = os.path.basename(backup_path)
            self.win._show_toast(f"Backup saved: {filename}")
        else:
            self.win._show_toast("Failed to create backup")

    def _restore_rules(self):
        backups = self.app.profiles.get_backups()
        if not backups:
            self.win._show_toast("No backups available to restore")
            return

        names = [b['filename'] for b in backups]
        combo = Gtk.DropDown.new_from_strings(names)
        dialog = Adw.AlertDialog(heading="Restore Firewall Configuration")
        dialog.set_extra_child(combo)
        dialog.add_response("cancel", "Cancel")
        dialog.add_response("restore", "Restore")
        dialog.set_response_appearance("restore", Adw.ResponseAppearance.DESTRUCTIVE)

        def on_resp(d, resp):
            if resp == "restore":
                idx = combo.get_selected()
                target_backup = backups[idx]['path']
                self.win._show_toast("Restoring firewall configuration...")

                def worker():
                    success, msg = self.app.profiles.restore_backup(target_backup, self.app.core)
                    def done():
                        if success:
                            self.app.fw_logger.log_event("config_changed", "warning", f"Restored backup: {names[idx]}")
                            self.win._show_toast("Firewall configuration restored")
                            self.refresh()
                        else:
                            self.win._show_toast(f"Restore: {msg}")
                    GLib.idle_add(done)

                threading.Thread(target=worker, daemon=True).start()
        dialog.connect("response", on_resp)
        dialog.present(self.win)


# =====================================================================
#  6. EVENT LOG PAGE (Corporate SIEM / Audit Log)
# =====================================================================

class LogsPage(Gtk.Box):
    def __init__(self, main_win):
        super().__init__(orientation=Gtk.Orientation.VERTICAL, spacing=10)
        self.win = main_win
        self.app = main_win.app
        self.set_margin_top(12)
        self.set_margin_bottom(12)
        self.set_margin_start(16)
        self.set_margin_end(16)

        # Filters toolbar
        bar = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10)
        self.search_logs = Gtk.SearchEntry(placeholder_text="Search audit log entries...")
        self.search_logs.set_hexpand(True)
        self.search_logs.connect("search-changed", lambda e: self.refresh())
        bar.append(self.search_logs)

        self.sev_filter = Gtk.DropDown.new_from_strings(["All Severities", "info", "warning", "alert", "critical"])
        self.sev_filter.connect("notify::selected-item", lambda d, p: self.refresh())
        bar.append(self.sev_filter)

        btn_export = Gtk.Button(label="Export Log")
        btn_export.connect("clicked", lambda b: self._dialog_export())
        bar.append(btn_export)

        btn_clear = Gtk.Button(label="Clear Log")
        btn_clear.set_css_classes(["destructive-action"])
        btn_clear.connect("clicked", lambda b: self._clear_log())
        bar.append(btn_clear)
        self.append(bar)

        # Log table
        scroll = Gtk.ScrolledWindow(vexpand=True)
        self.list_events = Gtk.ListBox()
        self.list_events.set_css_classes(["boxed-list"])
        scroll.set_child(self.list_events)
        self.append(scroll)

        # Footer stats
        self.lbl_stats = Gtk.Label()
        self.lbl_stats.set_css_classes(["dim-label", "caption"])
        self.lbl_stats.set_xalign(0)
        self.append(self.lbl_stats)

        self.refresh()

    def refresh(self):
        while (row := self.list_events.get_first_child()) is not None:
            self.list_events.remove(row)

        query = self.search_logs.get_text().strip()
        sev_str = self.sev_filter.get_selected_item().get_string()
        sev = None if sev_str == "All Severities" else sev_str

        events = self.app.fw_logger.get_events(count=200, severity=sev, search=query)

        if not events:
            self.list_events.append(Adw.ActionRow(title="No events match current filter"))
        else:
            for e in reversed(events):
                row = Adw.ActionRow()
                severity = e.get('severity', 'info')
                timestamp = e.get('timestamp', '')[:19].replace('T', ' ')
                
                row.set_title(f"[{severity.upper()}] {e.get('type')}: {e.get('details')}")
                row.set_subtitle(timestamp)

                icon_map = {
                    'info': ('dialog-information-symbolic', 'severity-info'),
                    'warning': ('dialog-warning-symbolic', 'severity-warning'),
                    'alert': ('security-low-symbolic', 'severity-alert'),
                    'critical': ('dialog-error-symbolic', 'severity-critical'),
                }
                icon_name, css_class = icon_map.get(severity, ('dialog-information-symbolic', 'severity-info'))
                img = Gtk.Image.new_from_icon_name(icon_name)
                img.set_css_classes([css_class])
                row.add_prefix(img)

                self.list_events.append(row)

        stats = self.app.fw_logger.get_stats()
        self.lbl_stats.set_label(
            f"Total Audit Events: {stats.get('total_events', 0)} | "
            f"Blocked Connections: {stats.get('blocked_connections', 0)} | "
            f"Rules Changed: {stats.get('rules_changed', 0)} | "
            f"Alerts: {stats.get('alerts', 0)}"
        )

    def _clear_log(self):
        self.app.fw_logger.clear_events()
        self.win._show_toast("Event log cleared")
        self.refresh()

    def _dialog_export(self):
        home_export = os.path.expanduser("~/firewall_events_export.json")
        if self.app.fw_logger.export_logs(home_export, fmt="json"):
            self.win._show_toast(f"Exported to {home_export}")
        else:
            self.win._show_toast("Failed to export logs")


# =====================================================================
#  7. SETTINGS PAGE
# =====================================================================

class SettingsPage(Gtk.ScrolledWindow):
    def __init__(self, main_win):
        super().__init__(vexpand=True, hexpand=True)
        self.win = main_win
        self.app = main_win.app

        clamp = Adw.Clamp(maximum_size=950, tightening_threshold=650)
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=20)
        box.set_margin_top(20)
        box.set_margin_bottom(30)
        box.set_margin_start(20)
        box.set_margin_end(20)
        clamp.set_child(box)
        self.set_child(clamp)

        # General Preferences
        grp_gen = Adw.PreferencesGroup(title="Application Preferences")
        
        row_min = Adw.ActionRow(title="Start Minimized", subtitle="Launch Vitorius Firewall silently to the system tray")
        self.sw_min = Gtk.Switch()
        self.sw_min.set_valign(Gtk.Align.CENTER)
        self.sw_min.set_active(self.app.profiles.get_setting("start_minimized", False))
        self.sw_min.connect("state-set", lambda s, state: self._update_setting("start_minimized", state))
        row_min.add_suffix(self.sw_min)
        grp_gen.add(row_min)

        row_panic = Adw.ActionRow(title="Require Confirmation for Panic Mode", subtitle="Ask before cutting all network connections")
        self.sw_panic = Gtk.Switch()
        self.sw_panic.set_valign(Gtk.Align.CENTER)
        self.sw_panic.set_active(self.app.profiles.get_setting("panic_mode_confirm", True))
        self.sw_panic.connect("state-set", lambda s, state: self._update_setting("panic_mode_confirm", state))
        row_panic.add_suffix(self.sw_panic)
        grp_gen.add(row_panic)

        row_autostart = Adw.ActionRow(
            title="Start with System on User Login",
            subtitle="Automatically launch Vitorius Firewall when you log in to your desktop session"
        )
        self.sw_autostart = Gtk.Switch()
        self.sw_autostart.set_valign(Gtk.Align.CENTER)
        self.sw_autostart.set_active(self._is_autostart_enabled())
        self.sw_autostart.connect("state-set", lambda s, state: self._toggle_autostart(state))
        row_autostart.add_suffix(self.sw_autostart)
        grp_gen.add(row_autostart)

        row_tray = Adw.ActionRow(
            title="Minimize to System Tray on Close",
            subtitle="Keep firewall active next to the network icon when closing the window"
        )
        self.sw_tray = Gtk.Switch()
        self.sw_tray.set_valign(Gtk.Align.CENTER)
        self.sw_tray.set_active(self.app.profiles.get_setting("close_to_tray", True))
        self.sw_tray.connect("state-set", lambda s, state: self._update_setting("close_to_tray", state))
        row_tray.add_suffix(self.sw_tray)
        grp_gen.add(row_tray)

        row_rate = Adw.ActionRow(
            title="Monitor Refresh Interval",
            subtitle="Frequency for updating real-time socket statistics and traffic counters"
        )
        self.combo_rate = Gtk.DropDown.new_from_strings(["High Speed (1s)", "Standard (2s)", "Low Overhead (4s)"])
        rate_val = self.app.profiles.get_setting("monitor_refresh_ms", 2000)
        rate_idx = 0 if rate_val == 1000 else (2 if rate_val == 4000 else 1)
        self.combo_rate.set_selected(rate_idx)
        self.combo_rate.connect("notify::selected-item", lambda d, p: self._on_rate_changed())
        row_rate.add_suffix(self.combo_rate)
        grp_gen.add(row_rate)

        row_autoscan = Adw.ActionRow(
            title="Auto-Scan Services on Startup",
            subtitle="Automatically discover listening daemons, system services, and applications on startup"
        )
        self.sw_autoscan = Gtk.Switch()
        self.sw_autoscan.set_valign(Gtk.Align.CENTER)
        self.sw_autoscan.set_active(self.app.profiles.get_setting("auto_scan_on_startup", True))
        self.sw_autoscan.connect("state-set", lambda s, state: self._update_setting("auto_scan_on_startup", state))
        row_autoscan.add_suffix(self.sw_autoscan)
        grp_gen.add(row_autoscan)

        row_scan_now = Adw.ActionRow(
            title="Scan Services &amp; Applications Now",
            subtitle="Trigger a full background discovery of system services and applications"
        )
        btn_scan_now = Gtk.Button(label="Run Scan")
        btn_scan_now.set_valign(Gtk.Align.CENTER)
        btn_scan_now.set_css_classes(["suggested-action"])
        btn_scan_now.connect("clicked", lambda b: self._trigger_scan())
        row_scan_now.add_suffix(btn_scan_now)
        grp_gen.add(row_scan_now)

        box.append(grp_gen)

        # System Diagnostics
        grp_diag = Adw.PreferencesGroup(title="Security Backend Diagnostics")
        
        row_fw = Adw.ActionRow(title="Firewalld Daemon", subtitle="Backend packet filtering service")
        lbl_fw_st = Gtk.Label(label=self.app.core.get_state())
        lbl_fw_st.set_css_classes(["status-good" if self.app.core.is_running() else "status-bad"])
        row_fw.add_suffix(lbl_fw_st)
        grp_diag.add(row_fw)

        row_nft = Adw.ActionRow(title="nftables Kernel Subsystem", subtitle="Low-level packet classification and NAT")
        lbl_nft = Gtk.Label(label="Available (Linux Kernel)")

        lbl_nft.set_css_classes(["dim-label"])
        row_nft.add_suffix(lbl_nft)
        grp_diag.add(row_nft)

        # Host Platform Detection (Fedora Linux)
        fedora_name, fedora_badge, fedora_css = self._get_host_platform_info()
        row_host = Adw.ActionRow(title="Host Platform", subtitle=fedora_name)
        lbl_host = Gtk.Label(label=fedora_badge)
        lbl_host.set_css_classes([fedora_css])
        row_host.add_suffix(lbl_host)
        grp_diag.add(row_host)

        box.append(grp_diag)

        # About / Version – read dynamically from default_config.json
        grp_about = Adw.PreferencesGroup(title="About Vitorius Firewall")
        cfg_version = self._read_version_from_config()
        self.row_version = Adw.ActionRow(
            title="Software Version",
            subtitle=f"Release {cfg_version} (Production Stable)"
        )
        self.lbl_version_badge = Gtk.Label(label=f"v{cfg_version}")
        self.lbl_version_badge.set_css_classes(["status-good"])
        self.row_version.add_suffix(self.lbl_version_badge)

        btn_about = Gtk.Button(label="About...")
        btn_about.set_valign(Gtk.Align.CENTER)
        btn_about.connect("clicked", lambda b: self.win._show_about_dialog())
        self.row_version.add_suffix(btn_about)
        grp_about.add(self.row_version)

        # Developer / Author
        row_creator = Adw.ActionRow(
            title="Created by Vitorius",
            subtitle="Original Author &amp; Lead Developer"
        )
        lbl_author_badge = Gtk.Label(label="Author")
        lbl_author_badge.set_css_classes(["status-good"])
        row_creator.add_suffix(lbl_author_badge)
        grp_about.add(row_creator)

        # License
        row_license = Adw.ActionRow(
            title="License",
            subtitle="MIT License — Copyright © 2026 Vitorius"
        )
        lbl_lic_badge = Gtk.Label(label="MIT")
        lbl_lic_badge.set_css_classes(["status-good"])
        row_license.add_suffix(lbl_lic_badge)

        btn_lic = Gtk.Button(label="View License")
        btn_lic.set_valign(Gtk.Align.CENTER)
        btn_lic.connect("clicked", lambda b: self.win._show_license_dialog())
        row_license.add_suffix(btn_lic)
        grp_about.add(row_license)

        box.append(grp_about)

        # Reset button
        btn_reset = Gtk.Button(label="Reset Application Settings to Default")
        btn_reset.set_css_classes(["destructive-action"])
        btn_reset.connect("clicked", lambda b: self._reset_settings())
        box.append(btn_reset)

    def _get_host_platform_info(self) -> tuple[str, str, str]:
        """Read /etc/os-release to detect Fedora version and platform details."""
        pretty_name = "Fedora Linux"
        is_fedora = False
        try:
            if os.path.exists('/etc/os-release'):
                data = {}
                with open('/etc/os-release', 'r', encoding='utf-8') as f:
                    for line in f:
                        if '=' in line:
                            k, v = line.strip().split('=', 1)
                            data[k.strip()] = v.strip().strip('"').strip("'")
                pretty_name = data.get('PRETTY_NAME', 'Fedora Linux')
                os_id = data.get('ID', '').lower()
                id_like = data.get('ID_LIKE', '').lower()
                if 'fedora' in os_id or 'fedora' in id_like:
                    is_fedora = True
        except Exception:
            pass

        if is_fedora:
            return pretty_name, "Fedora Verified", "status-good"
        else:
            return pretty_name, "Compatible (Fedora Optimized)", "status-info"

    def _read_version_from_config(self) -> str:
        """Load the version string from default_config.json.
        Returns 'unknown' if the file cannot be read or lacks a version key."""
        config_path = Path(__file__).resolve().parent.parent / "data" / "default_config.json"
        try:
            with open(config_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            return data.get("version", "unknown")
        except Exception as e:
            logger.error(f"Failed to read version from {config_path}: {e}")
            return "unknown"

    def _is_autostart_enabled(self) -> bool:
        autostart_file = Path.home() / ".config" / "autostart" / "vitorius-firewall.desktop"
        return autostart_file.is_file() and self.app.profiles.get_setting("autostart", False)

    def _toggle_autostart(self, state: bool) -> bool:
        if getattr(self, '_syncing', False):
            return False

        autostart_dir = Path.home() / ".config" / "autostart"
        autostart_file = autostart_dir / "vitorius-firewall.desktop"
        project_dir = Path(__file__).resolve().parent.parent
        run_sh = project_dir / "run.sh"

        try:
            if state:
                autostart_dir.mkdir(parents=True, exist_ok=True)
                content = (
                    "[Desktop Entry]\n"
                    "Version=1.30\n"
                    "Name=Vitorius Firewall\n"
                    "GenericName=Corporate Firewall Manager\n"
                    "Comment=Corporate-grade Windows-style firewall management with security profiles & live monitor\n"
                    f'Exec="{run_sh}" --minimized\n'
                    f'Path={project_dir}\n'
                    "Icon=com.vitorius.firewall\n"
                    "Terminal=false\n"
                    "Type=Application\n"
                    "Categories=System;Security;Settings;Network;\n"
                    "StartupNotify=false\n"
                    "StartupWMClass=com.vitorius.firewall\n"
                    "X-GNOME-Autostart-enabled=true\n"
                    "X-KDE-autostart-after=panel\n"
                    "X-KDE-autostart-phase=2\n"
                )
                autostart_file.write_text(content, encoding='utf-8')
                autostart_file.chmod(0o755)
                self.app.profiles.update_settings({"autostart": True, "auto_start": True})
                import subprocess
                subprocess.run(['systemctl', '--user', 'daemon-reload'], capture_output=True, timeout=3.0)
                self.win._show_toast("Vitorius Firewall will start automatically on login")
            else:
                if autostart_file.exists():
                    autostart_file.unlink()
                self.app.profiles.update_settings({"autostart": False, "auto_start": False})
                import subprocess
                subprocess.run(['systemctl', '--user', 'daemon-reload'], capture_output=True, timeout=3.0)
                self.win._show_toast("Autostart on login disabled")
        except Exception as e:
            logger.error(f"Error toggling autostart: {e}")
            self.win._show_toast(f"Failed to update autostart: {e}")
        return False

    def _on_rate_changed(self):
        if getattr(self, '_syncing', False):
            return
        idx = self.combo_rate.get_selected()
        rates = [1000, 2000, 4000]
        chosen = rates[idx] if idx < len(rates) else 2000
        self.app.profiles.update_settings({"monitor_refresh_ms": chosen})

    def _update_setting(self, key, value):
        if getattr(self, '_syncing', False):
            return False
        self.app.profiles.update_settings({key: value})
        return False

    def _trigger_scan(self):
        self.win._show_toast("Scanning services and applications...")
        self.win.trigger_service_scan()

    def _reset_settings(self):
        autostart_file = Path.home() / ".config" / "autostart" / "vitorius-firewall.desktop"
        if autostart_file.exists():
            try:
                autostart_file.unlink()
            except Exception:
                pass
        self.app.profiles.update_settings({
            "start_minimized": False,
            "panic_mode_confirm": True,
            "autostart": False,
            "close_to_tray": True,
            "monitor_refresh_ms": 2000,
            "auto_scan_on_startup": True,
        })
        self._syncing = True
        try:
            self.sw_min.set_active(False)
            self.sw_panic.set_active(True)
            self.sw_autostart.set_active(False)
            self.sw_tray.set_active(True)
            self.sw_autoscan.set_active(True)
            self.combo_rate.set_selected(1)
        finally:
            self._syncing = False
        self.win._show_toast("Settings restored to defaults")

    def refresh(self):
        self._syncing = True
        try:
            self.sw_autostart.set_active(self._is_autostart_enabled())
            self.sw_min.set_active(self.app.profiles.get_setting("start_minimized", False))
            self.sw_panic.set_active(self.app.profiles.get_setting("panic_mode_confirm", True))
            self.sw_tray.set_active(self.app.profiles.get_setting("close_to_tray", True))
            self.sw_autoscan.set_active(self.app.profiles.get_setting("auto_scan_on_startup", True))
            rate_val = self.app.profiles.get_setting("monitor_refresh_ms", 2000)
            rate_idx = 0 if rate_val == 1000 else (2 if rate_val == 4000 else 1)
            self.combo_rate.set_selected(rate_idx)
            # Update version dynamically on refresh
            cfg_version = self._read_version_from_config()
            if hasattr(self, 'lbl_version_badge') and self.lbl_version_badge:
                self.lbl_version_badge.set_label(f"v{cfg_version}")
            if hasattr(self, 'row_version') and self.row_version:
                self.row_version.set_subtitle(f"Release {cfg_version} (Production Stable)")
        finally:
            self._syncing = False
