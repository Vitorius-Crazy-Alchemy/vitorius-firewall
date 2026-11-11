Vitorius Firewall (v1.30)
Enterprise-Grade, GNOME-Native Linux Security Management Suite
Overview

Vitorius Firewall is an enterprise-grade, modern desktop security solution and firewall management suite built natively for Linux workstations and enterprise desktop distributions (including Fedora Linux, Red Hat Enterprise Linux, CentOS Stream, and Bazzite). Combining the low-overhead power of Linux kernel networking subsystems (firewalld and nftables) with a GTK4 and libadwaita interface, Vitorius Firewall delivers Windows Defender-style accessibility with Unix-grade packet filtering, policy auditing, and threat management.

Configuring Linux firewalls traditionally requires memorizing complex terminal commands (firewall-cmd, nft, or iptables) or relying on dated GTK2/GTK3 utilities that lack modern desktop integration. Vitorius Firewall resolves this disconnect by offering an accessible yet deep graphical dashboard. Whether you are an everyday desktop user needing standard home network security, a competitive gamer opening specific UDP ports with minimal input latency, a remote worker adhering to SOC 2 compliance, or a systems administrator locking down workstations into full drop-all containment, Vitorius Firewall delivers an all-in-one security command center.

Architectural Philosophy & Core Capabilities
1. Robust Dual-Engine Backend Architecture

Vitorius Firewall does not replace or fight against the operating system's native network architecture. Instead, it acts as an intelligent orchestration layer on top of firewalld (D-Bus and CLI) and the nftables kernel subsystem.

Stateful Packet Inspection (SPI): Real-time monitoring of TCP, UDP, ICMP, and RAW sockets directly through the /proc filesystem and Linux socket diagnostics (ss / netlink).
Policy Enforcement Without Interruption: Rule mutations, service authorizations, and IP blocks are executed permanently and reloaded dynamically, preventing network dropouts or broken state tables during normal updates.
Granular Zone Mapping: Full management over firewalld zones (home, work, public, drop, trusted, internal, and external), permitting custom interface binding and subnet filtering with instantaneous visual feedback.
2. Tailored Security Profiles

Vitorius Firewall introduces an automated Profile Management Subsystem providing pre-calibrated baseline postures:

Home: Everyday security balancing ease of use with essential protection. Permits trusted local discovery services (mdns, samba-client, dhcpv6-client, and local ssh) while discarding unsolicited external probes.
Public: Strict defensive posture optimized for untrusted Wi-Fi hotspots, public transit hubs, hotels, and airports. Disables broadcast discovery and locks down local listeners.
Corporate: Enterprise-aligned profile enforcing strict outgoing and incoming controls. Pre-configured for SOC 2 compliance standards, strict logging, intrusion defense telemetry, and granular port allowances (TCP 443 / 8443).
Gaming: High-performance, low-latency configuration. Automatically authorizes high-throughput gaming packet flows (Steam, Valve server ranges 27015-27030, STUN/VOIP ranges 3478-3480, and UDP voice channels) while maintaining strict background isolation.
Maximum Security (Lockdown Mode): Complete drop-all fortress mode aligned with HIPAA-grade isolation. Silently drops all unsolicited inbound traffic, reverses ICMP block configurations to evade ping sweep reconnaissance, and enforces strict outbound auditing.
3. Application & Service Auto-Discovery Scanner

Unlike traditional firewalls that expect users to know exact port numbers and transport protocols, Vitorius Firewall incorporates an intelligent ServiceAppScanner:

Listening Daemon Detection: Automatically detects running background network daemons (such as OpenSSH, CUPS, Syncthing, Cockpit, Nginx, PostgreSQL, MariaDB, and Jellyfin).
Desktop Application & Flatpak Awareness: Inspects sandbox manifests and active process trees to identify applications like Steam, Discord, Firefox, Chrome, Brave, and qBittorrent.
One-Click Authorization & Revocation: Toggle network access for entire applications and services instantly without having to construct manual rich rules.
4. Live Network Monitor & Socket Diagnostics

The built-in Network Monitor provides real-time visibility into your machine’s live communication surface:

Live Connection Table: Continuously audits open and established sockets, displaying process IDs (PID), binary names, local listening endpoints, remote peer addresses, protocol families, and current connection states (LISTEN, ESTABLISHED, TIME_WAIT).
Bandwidth & Interface Tracking: Real-time throughput metrics across wired (eth0, enp*), wireless (wlan0, wlp*), and virtual bridge (virbr0, docker0) interfaces.
Rapid Incident Response (Quick Block): Notice suspicious outbound beaconing or unwanted inbound connections? Block any IPv4/IPv6 address or CIDR subnet (e.g., 192.168.1.50 or 10.0.0.0/24) instantly with dedicated UI actions.
5. Panic Lockdown Protocol

In the event of an active intrusion, malware detonation, or suspicious outbound exfiltration, Vitorius Firewall features an instantaneous Panic Mode:

Triggerable directly from the main window header, the Dashboard quick actions, or the system tray context menu.
Immediately engages the kernel drop table to sever all incoming and outgoing network traffic across every interface.
Requires operator confirmation (configurable in settings) to prevent accidental engagement, with instant visual indicators across the UI.
6. Event Logging, Auditing & Export Capabilities
Local Security Audit Trail: Centralized logging of all profile switches, blocked connections, panic events, port alterations, and scanner activities.
JSON Rule Snapshot & Backup: Export the entire system firewall state—zones, ports, rich rules, and service configurations—into portable, timestamped JSON backups. Restore configurations seamlessly or migrate settings across multiple workstations.
Desktop Integration & User Experience

Designed specifically around the GNOME HIG (Human Interface Guidelines) and modern Linux desktop workflows:

Modern GTK4 & Libadwaita Interface: Dynamic adaptive split-view navigation that scales smoothly from high-resolution multi-monitor desktops to compact laptop displays and handheld gaming screens.
Background System Tray Indicator: Full StatusNotifierItem / AppIndicator support. Vitorius Firewall sits unobtrusively in your top bar or task tray, providing real-time status badges, quick profile switching, panic toggle, and instant access to the configuration panel.
Single-Instance IPC Daemon: Built-in UNIX domain socket server ensures subsequent application launches or desktop launcher clicks cleanly present the existing window without spawning duplicate background processes.
Smart Autostart Management: Optional background startup with minimized-to-tray execution on user session login, managed via standard XDG autostart standards and systemd user services.
Installation & System Requirements
Prerequisites
Operating System: Linux (Fedora 38+, RHEL 9+, CentOS Stream, Bazzite, or Debian/Ubuntu with firewalld installed)
Core Dependencies: Python 3.10+, GTK 4, Libadwaita 1.0+, PyGObject (python3-gobject), firewalld, nftables, iproute
Quick Start
bash
# Clone the repository
git clone https://github.com/YourUsername/vitorius-firewall.git
cd "vitorius-firewall"
# Run the automated installer
bash install.sh

The installer verifies existing versions, configures high-resolution vector and raster hicolor desktop icons, registers a single desktop entry (com.vitorius.firewall.desktop), updates the system desktop and icon databases, and launches the application.

Summary of Technical Specifications
Feature	Specification
Current Version	1.30 (Production Stable)
UI Toolkit	GTK4 + Libadwaita 1.0 (GNOME Native)
Backend Subsystems	firewalld (D-Bus / CLI) + nftables kernel filtering
Profiles Included	Home, Public, Corporate (SOC 2), Gaming, Maximum Security (HIPAA)
Monitoring	Socket inspection via /proc & netlink, live bandwidth metrics
App Discovery	System daemons, Flatpak applications, native binaries
Desktop Integration	System tray indicator, XDG autostart, IPC single-instance socket
License	Open Source under the MIT License

Vitorius Firewall — Built by Vitorius. Delivering accessible, robust, and transparent network security for modern Linux desktop environments.
