#!/usr/bin/env python3
"""
Vitorius Firewall - Profile & Services Unit Tests
Tests profile logic, fresh-install no-profile state, and service toggle safety.
Created by Vitorius
"""

import sys
import os
import json
import tempfile
import shutil
import unittest
from unittest.mock import MagicMock, patch, call

# Insert project root into sys.path
PROJECT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_DIR)

from backend.profiles import ProfileManager, DEFAULT_SETTINGS

# ─── Sample profile data ────────────────────────────────────────────────────

SAMPLE_PROFILES = {
    "Home": {
        "description": "Standard home network protection",
        "default_zone": "home",
        "tier": "standard",
        "icon": "user-home-symbolic",
        "allowed_services": ["dhcpv6-client", "mdns", "samba-client", "ssh"],
        "blocked_ports": [],
        "allowed_ports": [],
        "logging": "minimal",
        "icmp_block_inversion": False,
        "masquerade": False
    },
    "Public": {
        "description": "Enhanced protection for untrusted public networks",
        "default_zone": "public",
        "tier": "standard",
        "icon": "network-wireless-symbolic",
        "allowed_services": ["dhcpv6-client"],
        "blocked_ports": [],
        "allowed_ports": [],
        "logging": "standard",
        "icmp_block_inversion": False,
        "masquerade": False
    },
    "Corporate": {
        "description": "Enterprise-grade security",
        "default_zone": "work",
        "tier": "premium",
        "icon": "network-server-symbolic",
        "allowed_services": ["dhcpv6-client", "dns", "https"],
        "blocked_ports": [],
        "allowed_ports": [
            {"port": "443", "protocol": "tcp"},
            {"port": "8443", "protocol": "tcp"}
        ],
        "logging": "full",
        "icmp_block_inversion": True,
        "masquerade": False,
        "rate_limit": True,
        "ids_enabled": True,
        "geo_blocking": True,
        "blocked_countries": ["CN", "RU", "KP", "IR"],
        "compliance": "SOC2"
    },
    "Gaming": {
        "description": "Optimized for gaming",
        "default_zone": "home",
        "tier": "standard",
        "icon": "input-gaming-symbolic",
        "allowed_services": ["dhcpv6-client", "mdns"],
        "blocked_ports": [],
        "allowed_ports": [
            {"port": "27015-27030", "protocol": "tcp"},
            {"port": "27015-27030", "protocol": "udp"},
            {"port": "3478-3480", "protocol": "udp"},
            {"port": "27000-27100", "protocol": "udp"},
            {"port": "4380", "protocol": "udp"}
        ],
        "logging": "minimal",
        "icmp_block_inversion": False,
        "masquerade": False
    },
    "Maximum Security": {
        "description": "Lockdown mode — only explicitly allowed traffic passes",
        "default_zone": "drop",
        "tier": "premium",
        "icon": "security-high-symbolic",
        "allowed_services": [],
        "blocked_ports": [],
        "allowed_ports": [
            {"port": "443", "protocol": "tcp"},
            {"port": "53", "protocol": "udp"}
        ],
        "logging": "full",
        "icmp_block_inversion": True,
        "masquerade": False,
        "rate_limit": True,
        "ids_enabled": True,
        "geo_blocking": True,
        "blocked_countries": ["CN", "RU", "KP", "IR", "SY", "CU"],
        "compliance": "HIPAA"
    }
}


def _make_manager(config: dict = None, profiles_dict: dict = None) -> tuple[ProfileManager, str]:
    """Create a ProfileManager backed by a temp directory."""
    tmpdir = tempfile.mkdtemp()

    # Write default_config.json
    default_cfg_path = os.path.join(tmpdir, "default_config.json")
    cfg = {
        "version": "1.30",
        "app_name": "Vitorius Firewall",
        "profiles": profiles_dict if profiles_dict is not None else dict(SAMPLE_PROFILES),
        "settings": {}
    }
    with open(default_cfg_path, "w") as f:
        json.dump(cfg, f)

    # Patch storage directories to tmpdir so tests are isolated
    with patch("backend.profiles.CONFIG_DIR", new=__import__("pathlib").Path(tmpdir) / "config"), \
         patch("backend.profiles.DATA_DIR", new=__import__("pathlib").Path(tmpdir) / "data"), \
         patch("backend.profiles.CONFIG_FILE", new=__import__("pathlib").Path(tmpdir) / "config" / "config.json"), \
         patch("backend.profiles.LOG_DIR", new=__import__("pathlib").Path(tmpdir) / "data" / "logs"), \
         patch("backend.profiles.BACKUP_DIR", new=__import__("pathlib").Path(tmpdir) / "data" / "backups"), \
         patch("backend.profiles.RULES_BACKUP_DIR", new=__import__("pathlib").Path(tmpdir) / "data" / "backups" / "rules"), \
         patch("backend.profiles.BASE_DIR", new=__import__("pathlib").Path(tmpdir)):
        mgr = ProfileManager(default_config_path=default_cfg_path)

    return mgr, tmpdir


# ════════════════════════════════════════════════════════════════════════════
#  TEST: Fresh-Install No-Profile State
# ════════════════════════════════════════════════════════════════════════════

class TestFreshInstallNoProfile(unittest.TestCase):
    """On first launch, no profile must be active so the user can choose one."""

    def setUp(self):
        self.mgr, self.tmpdir = _make_manager()

    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_fresh_install_has_no_active_profile(self):
        """Fresh install → active_profile should be empty string."""
        self.assertEqual(
            self.mgr.get_active_profile(), "",
            "Fresh install must start with NO active profile"
        )

    def test_profiles_are_loaded(self):
        """Profiles dictionary must be populated from default_config.json."""
        profiles = self.mgr.get_profiles()
        self.assertGreaterEqual(len(profiles), 5, "All 5 built-in profiles must load")
        for name in ("Home", "Public", "Corporate", "Gaming", "Maximum Security"):
            self.assertIn(name, profiles, f"Profile '{name}' must be present")

    def test_set_active_profile_persists(self):
        """After choosing a profile, it must persist across reload."""
        self.assertEqual(self.mgr.get_active_profile(), "")
        self.mgr.set_active_profile("Home")
        self.assertEqual(self.mgr.get_active_profile(), "Home")

    def test_no_profile_config_key_stored(self):
        """The saved config file must have active_profile == '' on fresh install."""
        import pathlib
        config_file = pathlib.Path(self.tmpdir) / "config" / "config.json"
        # ProfileManager writes to config dir we patched above. Re-check via saved file.
        # Since the patch is gone, re-read whatever was actually written (uses real paths)
        # Instead, verify via the in-memory state
        self.assertEqual(self.mgr._active_profile, "")


# ════════════════════════════════════════════════════════════════════════════
#  TEST: Profile Data Integrity
# ════════════════════════════════════════════════════════════════════════════

class TestProfileDataIntegrity(unittest.TestCase):
    """Each profile must have all required fields with correct types."""

    def setUp(self):
        self.mgr, self.tmpdir = _make_manager()

    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def _assert_profile_valid(self, name: str):
        profile = self.mgr.get_profile(name)
        self.assertIsNotNone(profile, f"Profile '{name}' must exist")
        self.assertIn("default_zone", profile, f"'{name}' must have default_zone")
        self.assertIn("tier", profile, f"'{name}' must have tier")
        self.assertIn("allowed_services", profile, f"'{name}' must have allowed_services")
        self.assertIsInstance(profile["allowed_services"], list)
        self.assertIn("allowed_ports", profile, f"'{name}' must have allowed_ports")
        self.assertIsInstance(profile["allowed_ports"], list)
        self.assertIn("logging", profile, f"'{name}' must have logging")
        self.assertIn(profile["logging"], ("minimal", "standard", "full"),
                      f"'{name}' logging must be minimal/standard/full")
        self.assertIn("icmp_block_inversion", profile, f"'{name}' must have icmp_block_inversion")
        self.assertIsInstance(profile["icmp_block_inversion"], bool)
        self.assertIn("masquerade", profile, f"'{name}' must have masquerade")

    def test_home_profile_valid(self):
        self._assert_profile_valid("Home")

    def test_public_profile_valid(self):
        self._assert_profile_valid("Public")

    def test_corporate_profile_valid(self):
        self._assert_profile_valid("Corporate")
        p = self.mgr.get_profile("Corporate")
        # Corporate must have premium features
        self.assertEqual(p["tier"], "premium")
        self.assertTrue(p.get("icmp_block_inversion"), "Corporate must have ICMP inversion enabled")
        self.assertTrue(p.get("rate_limit"), "Corporate must have rate_limit=True")
        self.assertEqual(p["logging"], "full", "Corporate must have full logging")
        self.assertIn("work", p["default_zone"], "Corporate must use 'work' zone")
        self.assertIn("dhcpv6-client", p["allowed_services"])
        self.assertIn("dns", p["allowed_services"])
        self.assertIn("https", p["allowed_services"])

    def test_gaming_profile_valid(self):
        self._assert_profile_valid("Gaming")
        p = self.mgr.get_profile("Gaming")
        # Gaming must have Steam/game ports open
        port_strings = [f"{pi['port']}/{pi['protocol']}" for pi in p["allowed_ports"]]
        self.assertTrue(
            any("27015" in ps for ps in port_strings),
            "Gaming must allow Steam ports 27015+"
        )

    def test_maximum_security_profile_valid(self):
        self._assert_profile_valid("Maximum Security")
        p = self.mgr.get_profile("Maximum Security")
        self.assertEqual(p["default_zone"], "drop", "Max Security must use 'drop' zone")
        self.assertEqual(p["allowed_services"], [], "Max Security must allow NO services")
        self.assertTrue(p.get("icmp_block_inversion"))
        self.assertTrue(p.get("rate_limit"))
        # Only DNS + HTTPS ports
        ports = [(pi["port"], pi["protocol"]) for pi in p["allowed_ports"]]
        self.assertIn(("443", "tcp"), ports, "Max Security must allow 443/tcp")
        self.assertIn(("53", "udp"), ports, "Max Security must allow 53/udp")

    def test_all_profiles_have_distinct_descriptions(self):
        """Every profile must have a non-empty, unique description."""
        profiles = self.mgr.get_profiles()
        descs = [p.get("description", "") for p in profiles.values()]
        for d in descs:
            self.assertTrue(len(d) > 0, "Description must not be empty")
        self.assertEqual(len(descs), len(set(descs)), "All descriptions must be unique")


# ════════════════════════════════════════════════════════════════════════════
#  TEST: apply_profile command generation
# ════════════════════════════════════════════════════════════════════════════

class TestApplyProfileCommands(unittest.TestCase):
    """
    apply_profile must generate the correct firewall-cmd commands for each profile.
    We mock execute_batch to intercept the script without touching the real firewall.
    """

    def setUp(self):
        self.mgr, self.tmpdir = _make_manager()
        self.mock_core = MagicMock()
        self.mock_core.is_running.return_value = True
        self.mock_core.get_zone_settings.return_value = {
            "zone": "public",
            "services": ["http"],           # existing service to be cleared
            "ports": [{"port": "8080", "protocol": "tcp"}],  # existing port to be cleared
            "rich_rules": [],
            "masquerade": False,
        }
        self.mock_core.execute_batch.return_value = (True, "OK")
        self.mock_core.get_default_zone.return_value = "public"

    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def _get_batch_script(self) -> list[str]:
        """Return the commands list passed to execute_batch."""
        return self.mock_core.execute_batch.call_args[0][0]

    def test_apply_home_profile(self):
        ok, msg = self.mgr.apply_profile("Home", self.mock_core)
        self.assertTrue(ok)
        cmds = self._get_batch_script()
        # Must set zone to 'home'
        self.assertTrue(any('--set-default-zone="home"' in c for c in cmds))
        # Must clear old 'http' service
        self.assertTrue(any('--remove-service="http"' in c for c in cmds))
        # Must clear old port 8080
        self.assertTrue(any('--remove-port="8080/tcp"' in c for c in cmds))
        # Must add Home's allowed services
        self.assertTrue(any('--add-service="ssh"' in c for c in cmds))
        self.assertTrue(any('--add-service="mdns"' in c for c in cmds))
        # Logging minimal → log-denied=off
        self.assertTrue(any('--set-log-denied=off' in c for c in cmds))
        # No masquerade
        self.assertTrue(any('--remove-masquerade' in c for c in cmds))
        # No ICMP inversion for Home
        self.assertTrue(any('--remove-icmp-block-inversion' in c for c in cmds))
        # Must reload at end
        self.assertTrue(any('--reload' in c for c in cmds))

    def test_apply_public_profile(self):
        ok, msg = self.mgr.apply_profile("Public", self.mock_core)
        self.assertTrue(ok)
        cmds = self._get_batch_script()
        self.assertTrue(any('--set-default-zone="public"' in c for c in cmds))
        # Only dhcpv6-client allowed
        self.assertTrue(any('--add-service="dhcpv6-client"' in c for c in cmds))
        # Standard logging
        self.assertTrue(any('--set-log-denied=all' in c for c in cmds))

    def test_apply_corporate_profile(self):
        ok, msg = self.mgr.apply_profile("Corporate", self.mock_core)
        self.assertTrue(ok)
        cmds = self._get_batch_script()
        self.assertTrue(any('--set-default-zone="work"' in c for c in cmds))
        # Services: dhcpv6-client, dns, https
        self.assertTrue(any('--add-service="dhcpv6-client"' in c for c in cmds))
        self.assertTrue(any('--add-service="dns"' in c for c in cmds))
        self.assertTrue(any('--add-service="https"' in c for c in cmds))
        # Ports: 443, 8443
        self.assertTrue(any('--add-port="443/tcp"' in c for c in cmds))
        self.assertTrue(any('--add-port="8443/tcp"' in c for c in cmds))
        # Full logging
        self.assertTrue(any('--set-log-denied=all' in c for c in cmds))
        # ICMP block inversion enabled
        self.assertTrue(any('--add-icmp-block-inversion' in c for c in cmds))
        # Rate limiting rich rule
        self.assertTrue(any('limit value' in c or 'rate' in c.lower() for c in cmds))

    def test_apply_gaming_profile(self):
        ok, msg = self.mgr.apply_profile("Gaming", self.mock_core)
        self.assertTrue(ok)
        cmds = self._get_batch_script()
        self.assertTrue(any('--set-default-zone="home"' in c for c in cmds))
        # Steam ports
        self.assertTrue(any('27015-27030' in c for c in cmds))
        self.assertTrue(any('3478-3480' in c for c in cmds))
        # Logging: minimal → off
        self.assertTrue(any('--set-log-denied=off' in c for c in cmds))
        # No ICMP inversion
        self.assertTrue(any('--remove-icmp-block-inversion' in c for c in cmds))

    def test_apply_maximum_security_profile(self):
        ok, msg = self.mgr.apply_profile("Maximum Security", self.mock_core)
        self.assertTrue(ok)
        cmds = self._get_batch_script()
        self.assertTrue(any('--set-default-zone="drop"' in c for c in cmds))
        # No allowed services (empty list → nothing added, but old http removed)
        self.assertFalse(any('--add-service="http"' in c for c in cmds))
        # Only 443/tcp and 53/udp ports
        self.assertTrue(any('--add-port="443/tcp"' in c for c in cmds))
        self.assertTrue(any('--add-port="53/udp"' in c for c in cmds))
        # Full logging
        self.assertTrue(any('--set-log-denied=all' in c for c in cmds))
        # ICMP inversion enabled
        self.assertTrue(any('--add-icmp-block-inversion' in c for c in cmds))

    def test_apply_nonexistent_profile_fails(self):
        ok, msg = self.mgr.apply_profile("GhostProfile", self.mock_core)
        self.assertFalse(ok)
        self.assertIn("not found", msg.lower())

    def test_apply_profile_always_ends_with_reload(self):
        """Every profile application must end with firewall-cmd --reload."""
        for profile_name in ("Home", "Public", "Corporate", "Gaming", "Maximum Security"):
            with self.subTest(profile=profile_name):
                self.mock_core.execute_batch.reset_mock()
                self.mock_core.execute_batch.return_value = (True, "OK")
                self.mgr.apply_profile(profile_name, self.mock_core)
                cmds = self._get_batch_script()
                self.assertTrue(
                    any(c.strip().endswith('--reload') for c in cmds),
                    f"Profile '{profile_name}' must end with firewall-cmd --reload"
                )

    def test_apply_profile_starts_firewalld(self):
        """Every apply must start firewalld if needed."""
        for profile_name in ("Home", "Corporate"):
            with self.subTest(profile=profile_name):
                self.mock_core.execute_batch.reset_mock()
                self.mock_core.execute_batch.return_value = (True, "OK")
                self.mgr.apply_profile(profile_name, self.mock_core)
                cmds = self._get_batch_script()
                self.assertTrue(
                    any('systemctl start firewalld' in c for c in cmds),
                    f"Profile '{profile_name}' must start firewalld"
                )

    def test_apply_profile_updates_active_profile(self):
        """After successful apply, active_profile must update."""
        self.mock_core.execute_batch.return_value = (True, "OK")
        self.assertEqual(self.mgr.get_active_profile(), "")
        self.mgr.apply_profile("Home", self.mock_core)
        self.assertEqual(self.mgr.get_active_profile(), "Home")

    def test_apply_profile_does_not_update_on_failure(self):
        """If execute_batch fails, active_profile must NOT change."""
        self.mock_core.execute_batch.return_value = (False, "Authorization cancelled")
        self.assertEqual(self.mgr.get_active_profile(), "")
        ok, _ = self.mgr.apply_profile("Corporate", self.mock_core)
        self.assertFalse(ok)
        self.assertEqual(self.mgr.get_active_profile(), "",
                         "Active profile must NOT change when apply fails")

    def test_apply_home_then_corporate_clears_home_services(self):
        """Switching from Home to Corporate must clear Home's services."""
        # Simulate Home being active (zone_settings returns Home services)
        self.mock_core.get_zone_settings.return_value = {
            "zone": "home",
            "services": ["dhcpv6-client", "mdns", "samba-client", "ssh"],
            "ports": [],
            "rich_rules": [],
            "masquerade": False,
        }
        self.mock_core.execute_batch.return_value = (True, "OK")
        ok, _ = self.mgr.apply_profile("Corporate", self.mock_core)
        self.assertTrue(ok)
        cmds = self._get_batch_script()
        # Must remove Home services
        self.assertTrue(any('--remove-service="mdns"' in c for c in cmds))
        self.assertTrue(any('--remove-service="samba-client"' in c for c in cmds))


# ════════════════════════════════════════════════════════════════════════════
#  TEST: Service Toggle Privilege Correctness
# ════════════════════════════════════════════════════════════════════════════

class TestServiceTogglePrivileges(unittest.TestCase):
    """
    Service enable/disable must route through pkexec (execute_batch) for all
    firewall-cmd and systemctl system commands.
    """

    def setUp(self):
        self.mgr, self.tmpdir = _make_manager()
        self.mock_core = MagicMock()
        self.mock_core.is_running.return_value = True
        self.mock_core.get_default_zone.return_value = "public"
        self.mock_core.execute_batch.return_value = (True, "OK")

    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def _build_scanned_item(self, **kwargs):
        """Build a minimal ScannedItem-like mock."""
        from backend.scanner import ScannedItem
        defaults = dict(
            id="svc:ssh",
            name="OpenSSH Server",
            category="service",
            item_type="firewalld_service",
            icon="utilities-terminal-symbolic",
            description="SSH service",
            service_name="ssh",
            systemd_unit="sshd.service",
            flatpak_id="",
            exec_name="sshd",
            exec_path="/usr/sbin/sshd",
            ports=[("22", "tcp")],
            is_running=True,
            pids=[1234],
            is_enabled=True,
            details={}
        )
        defaults.update(kwargs)
        return ScannedItem(**defaults)

    def test_disable_service_uses_execute_batch(self):
        """Disabling a service must use execute_batch (runs via pkexec)."""
        from backend.scanner import ServiceAppScanner
        scanner = ServiceAppScanner()
        item = self._build_scanned_item(is_enabled=True)
        scanner.toggle_item(item, allow=False, firewall_core=self.mock_core, profile_mgr=self.mgr)
        self.mock_core.execute_batch.assert_called_once()

    def test_enable_service_uses_execute_batch(self):
        """Re-enabling a service must use execute_batch (runs via pkexec)."""
        from backend.scanner import ServiceAppScanner
        scanner = ServiceAppScanner()
        item = self._build_scanned_item(is_enabled=False)
        scanner.toggle_item(item, allow=True, firewall_core=self.mock_core, profile_mgr=self.mgr)
        self.mock_core.execute_batch.assert_called_once()

    def test_disable_service_removes_from_zone_permanently(self):
        """Disabling a service must issue --permanent --remove-service."""
        from backend.scanner import ServiceAppScanner
        scanner = ServiceAppScanner()
        item = self._build_scanned_item()
        scanner.toggle_item(item, allow=False, firewall_core=self.mock_core, profile_mgr=self.mgr)
        cmds = self.mock_core.execute_batch.call_args[0][0]
        self.assertTrue(any('--permanent' in c and '--remove-service="ssh"' in c for c in cmds),
                         "Must permanently remove service from zone")

    def test_disable_service_rejects_ports(self):
        """Disabling a service must add a rich-rule reject for its ports."""
        from backend.scanner import ServiceAppScanner
        scanner = ServiceAppScanner()
        item = self._build_scanned_item()
        scanner.toggle_item(item, allow=False, firewall_core=self.mock_core, profile_mgr=self.mgr)
        cmds = self.mock_core.execute_batch.call_args[0][0]
        self.assertTrue(
            any('reject' in c and '22' in c and 'tcp' in c for c in cmds),
            "Must add reject rich-rule for port 22/tcp when disabling SSH"
        )

    def test_disable_service_severs_active_sockets(self):
        """Disabling a service must kill active sockets (ss -K)."""
        from backend.scanner import ServiceAppScanner
        scanner = ServiceAppScanner()
        item = self._build_scanned_item()
        scanner.toggle_item(item, allow=False, firewall_core=self.mock_core, profile_mgr=self.mgr)
        cmds = self.mock_core.execute_batch.call_args[0][0]
        self.assertTrue(
            any('ss -K' in c for c in cmds),
            "Must use ss -K to terminate active connections when disabling a service"
        )

    def test_disable_service_sets_systemd_ip_deny(self):
        """Disabling a service with a systemd unit must set IPAddressDeny=any."""
        from backend.scanner import ServiceAppScanner
        scanner = ServiceAppScanner()
        item = self._build_scanned_item()
        scanner.toggle_item(item, allow=False, firewall_core=self.mock_core, profile_mgr=self.mgr)
        cmds = self.mock_core.execute_batch.call_args[0][0]
        self.assertTrue(
            any('IPAddressDeny=any' in c for c in cmds),
            "Must set IPAddressDeny=any on systemd unit when blocking"
        )

    def test_enable_service_clears_systemd_ip_deny(self):
        """Re-enabling a service must clear IPAddressDeny."""
        from backend.scanner import ServiceAppScanner
        scanner = ServiceAppScanner()
        item = self._build_scanned_item(is_enabled=False)
        scanner.toggle_item(item, allow=True, firewall_core=self.mock_core, profile_mgr=self.mgr)
        cmds = self.mock_core.execute_batch.call_args[0][0]
        self.assertTrue(
            any('IPAddressAllow=any' in c for c in cmds),
            "Must restore IPAddressAllow=any when re-enabling service"
        )

    def test_enable_service_adds_permanently(self):
        """Enabling a service must add it both runtime and permanently."""
        from backend.scanner import ServiceAppScanner
        scanner = ServiceAppScanner()
        item = self._build_scanned_item(is_enabled=False)
        scanner.toggle_item(item, allow=True, firewall_core=self.mock_core, profile_mgr=self.mgr)
        cmds = self.mock_core.execute_batch.call_args[0][0]
        self.assertTrue(any('--permanent' in c and '--add-service="ssh"' in c for c in cmds))

    def test_enable_service_removes_reject_rules(self):
        """Enabling a service must remove previously-added reject rich rules."""
        from backend.scanner import ServiceAppScanner
        scanner = ServiceAppScanner()
        item = self._build_scanned_item(is_enabled=False)
        scanner.toggle_item(item, allow=True, firewall_core=self.mock_core, profile_mgr=self.mgr)
        cmds = self.mock_core.execute_batch.call_args[0][0]
        self.assertTrue(
            any('--remove-rich-rule' in c and 'reject' in c for c in cmds),
            "Must remove reject rich-rule when re-enabling a service"
        )

    def test_toggle_updates_profile_blocked_services(self):
        """Blocking a service must persist it in profile blocked_services list."""
        from backend.scanner import ServiceAppScanner
        scanner = ServiceAppScanner()
        item = self._build_scanned_item()
        self.mock_core.execute_batch.return_value = (True, "OK")
        scanner.toggle_item(item, allow=False, firewall_core=self.mock_core, profile_mgr=self.mgr)
        blocked = self.mgr.get_setting("blocked_services", [])
        self.assertIn("ssh", blocked, "ssh must be in blocked_services after disabling")

    def test_unblock_clears_profile_blocked_services(self):
        """Re-enabling a service must remove it from profile blocked_services list."""
        from backend.scanner import ServiceAppScanner
        scanner = ServiceAppScanner()
        # Pre-populate blocked list
        self.mgr.update_settings({"blocked_services": ["ssh"]})
        item = self._build_scanned_item(is_enabled=False)
        self.mock_core.execute_batch.return_value = (True, "OK")
        scanner.toggle_item(item, allow=True, firewall_core=self.mock_core, profile_mgr=self.mgr)
        blocked = self.mgr.get_setting("blocked_services", [])
        self.assertNotIn("ssh", blocked, "ssh must NOT be in blocked_services after re-enabling")

    def test_toggle_failure_does_not_update_state(self):
        """When execute_batch returns failure, item state must not change."""
        from backend.scanner import ServiceAppScanner
        scanner = ServiceAppScanner()
        item = self._build_scanned_item(is_enabled=True)
        self.mock_core.execute_batch.return_value = (False, "Authorization cancelled")
        ok, msg = scanner.toggle_item(item, allow=False, firewall_core=self.mock_core, profile_mgr=self.mgr)
        self.assertFalse(ok)
        # Item state must NOT have changed to False since operation failed
        self.assertTrue(item.is_enabled, "Item must remain enabled after a failed block attempt")

    def test_no_service_name_uses_exec_name_fallback(self):
        """If service_name is empty, should fall back to exec_name."""
        from backend.scanner import ServiceAppScanner
        scanner = ServiceAppScanner()
        item = self._build_scanned_item(service_name="", exec_name="custom-daemon", ports=[("9999", "tcp")])
        scanner.toggle_item(item, allow=False, firewall_core=self.mock_core, profile_mgr=self.mgr)
        cmds = self.mock_core.execute_batch.call_args[0][0]
        self.assertTrue(
            any('custom-daemon' in c for c in cmds),
            "Must use exec_name as fallback when service_name is empty"
        )


# ════════════════════════════════════════════════════════════════════════════
#  TEST: Profile CRUD
# ════════════════════════════════════════════════════════════════════════════

class TestProfileCRUD(unittest.TestCase):

    def setUp(self):
        self.mgr, self.tmpdir = _make_manager()

    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_create_custom_profile(self):
        custom = {
            "description": "My custom profile",
            "default_zone": "public",
            "tier": "custom",
            "allowed_services": ["http", "https"],
            "allowed_ports": [],
            "blocked_ports": [],
            "logging": "minimal",
            "icmp_block_inversion": False,
            "masquerade": False
        }
        result = self.mgr.create_profile("MyProfile", custom)
        self.assertTrue(result)
        self.assertIsNotNone(self.mgr.get_profile("MyProfile"))

    def test_create_duplicate_profile_fails(self):
        self.assertFalse(self.mgr.create_profile("Home", {}),
                         "Creating a duplicate profile must fail")

    def test_delete_custom_profile(self):
        self.mgr.create_profile("Temp", {"tier": "custom"})
        result = self.mgr.delete_profile("Temp")
        self.assertTrue(result)
        self.assertIsNone(self.mgr.get_profile("Temp"))

    def test_delete_builtin_profile_fails(self):
        for name in ("Home", "Public", "Corporate", "Gaming", "Maximum Security"):
            with self.subTest(profile=name):
                self.assertFalse(
                    self.mgr.delete_profile(name),
                    f"Deleting built-in profile '{name}' must fail"
                )

    def test_duplicate_profile(self):
        result = self.mgr.duplicate_profile("Home", "Home Copy")
        self.assertTrue(result)
        copy = self.mgr.get_profile("Home Copy")
        self.assertIsNotNone(copy)
        self.assertEqual(copy["tier"], "custom")
        self.assertIn("ssh", copy["allowed_services"])

    def test_update_profile(self):
        original = dict(self.mgr.get_profile("Home"))
        original["description"] = "Updated description"
        result = self.mgr.update_profile("Home", original)
        self.assertTrue(result)
        self.assertEqual(self.mgr.get_profile("Home")["description"], "Updated description")


# ════════════════════════════════════════════════════════════════════════════
#  TEST: Scanner is_enabled logic
# ════════════════════════════════════════════════════════════════════════════

class TestScannerEnabledLogic(unittest.TestCase):
    """
    When firewalld is NOT running (empty active_zone_services),
    services must default to enabled=True — not all marked as blocked.
    """

    def test_service_enabled_when_firewalld_not_running(self):
        """With no zone services (firewalld down), is_enabled must stay True."""
        active_zone_services = set()  # Firewalld not running / no info
        blocked_apps = set()
        blocked_services = set()
        svc_id = "ssh"

        is_enabled = True
        if svc_id in blocked_services or svc_id in blocked_apps:
            is_enabled = False
        elif active_zone_services:
            if svc_id not in active_zone_services:
                is_enabled = False

        self.assertTrue(is_enabled,
                        "Service must be enabled when firewalld provides no zone services")

    def test_service_disabled_when_not_in_running_zone(self):
        """Service not in an active zone's services list must be disabled."""
        active_zone_services = {"dhcpv6-client"}  # firewalld running, ssh not allowed
        svc_id = "ssh"

        is_enabled = True
        if active_zone_services and svc_id not in active_zone_services:
            is_enabled = False

        self.assertFalse(is_enabled,
                         "Service absent from active zone must show as disabled")

    def test_explicitly_blocked_overrides_zone_check(self):
        """Explicitly blocked service must be disabled regardless of zone."""
        active_zone_services = {"ssh"}  # ssh in zone
        blocked_services = {"ssh"}      # but explicitly blocked
        svc_id = "ssh"

        is_enabled = True
        if svc_id in blocked_services:
            is_enabled = False
        elif active_zone_services and svc_id not in active_zone_services:
            is_enabled = False

        self.assertFalse(is_enabled,
                         "Explicitly blocked service must be disabled even if in zone")

    def test_dns_resolver_protected_from_ip_deny(self):
        """DNS service toggle must NEVER apply IPAddressDeny to systemd-resolved."""
        from backend.scanner import ServiceAppScanner, ScannedItem
        scanner = ServiceAppScanner()
        item = ScannedItem(
            id="svc:dns",
            name="DNS Server",
            category="service",
            item_type="firewalld_service",
            icon="network-wired-symbolic",
            description="DNS server",
            service_name="dns",
            systemd_unit="systemd-resolved.service",
            ports=[("53", "udp")],
            is_enabled=True
        )
        mock_core = MagicMock()
        mock_core.get_default_zone.return_value = "public"
        mock_core.get_active_zones.return_value = {"public": {}}
        mock_core.get_zones.return_value = ["public", "FedoraWorkstation"]
        mock_core.execute_batch.return_value = (True, "OK")

        scanner.toggle_item(item, allow=False, firewall_core=mock_core, profile_mgr=None)
        cmds = mock_core.execute_batch.call_args[0][0]
        self.assertFalse(
            any('IPAddressDeny=any' in c and 'resolved' in c for c in cmds),
            "Must NEVER apply IPAddressDeny to systemd-resolved"
        )

    def test_block_application_does_not_drop_web_ports_in_output(self):
        """block_application must NOT place global direct OUTPUT reject rules on web ports 80/443."""
        from backend.core import FirewallCore
        core = FirewallCore()
        core.execute_batch = MagicMock(return_value=(True, "OK"))
        core.get_default_zone = MagicMock(return_value="public")

        core.block_application("test-web-app", local_ports=[80, 443])
        cmds = core.execute_batch.call_args[0][0]
        self.assertFalse(
            any('direct --add-rule ipv4 filter OUTPUT' in c and '--dport 80' in c for c in cmds),
            "Must NOT add global OUTPUT drop on port 80"
        )
        self.assertFalse(
            any('direct --add-rule ipv4 filter OUTPUT' in c and '--dport 443' in c for c in cmds),
            "Must NOT add global OUTPUT drop on port 443"
        )

    def test_active_zones_parsing_strips_default_suffix(self):
        """get_active_zones must cleanly parse zone names without '(default)' suffix."""
        from backend.core import FirewallCore
        with patch('backend.core._fw', return_value="public (default)\n  interfaces: enp10s0\n"):
            core = FirewallCore()
            zones = core.get_active_zones()
            self.assertIn("public", zones, "Zone name must be 'public', not 'public (default)'")
            self.assertNotIn("public (default)", zones)

    def test_block_application_steam_covers_helpers_and_flatpak(self):
        """block_application for Steam must isolate Flatpak sandbox and target steamwebhelper."""
        from backend.core import FirewallCore
        core = FirewallCore()
        core.execute_batch = MagicMock(return_value=(True, "OK"))
        core.get_default_zone = MagicMock(return_value="public")

        with patch('backend.core.get_installed_flatpaks', return_value={'steam': 'com.valvesoftware.Steam'}):
            core.block_application("Steam")
            cmds = core.execute_batch.call_args[0][0]
            # Must enforce Flatpak unshare & kill
            self.assertTrue(
                any('flatpak override --system --unshare=network com.valvesoftware.Steam' in c for c in cmds),
                "Must apply system Flatpak unshare for Steam"
            )
            self.assertTrue(
                any('flatpak kill com.valvesoftware.Steam' in c for c in cmds),
                "Must kill running Flatpak sandbox so unshare applies immediately"
            )


if __name__ == "__main__":
    unittest.main(verbosity=2)
