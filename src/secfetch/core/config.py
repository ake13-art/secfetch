from pathlib import Path
import configparser

CONFIG_PATH = Path.home() / ".config" / "secfetch" / "checks.conf"

DEFAULT_CONFIG = """
[checks]
# --- fastscan: fast checks, no filesystem traversal ---
aslr = true
secure_boot = true
kernel_version = true
lockdown = true
firewall = true
ports = true
ptrace_scope = true
dmesg_restrict = true
tcp_syncookies = true
rp_filter = true

# --- fullscan only: slow or lower priority ---
lsm = false
kptr_restrict = false
modules_disabled = false
bpf_hardening = false
ipv6 = false
world_writable = false
suid = false
tmp_noexec = false
sticky_tmp = false
firewall_rules = false
services = false
"""


def load_config() -> configparser.ConfigParser:
    # Create default config on first run, then read it
    config = configparser.ConfigParser()
    if not CONFIG_PATH.exists():
        CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
        CONFIG_PATH.write_text(DEFAULT_CONFIG.strip())
    config.read(CONFIG_PATH)
    return config


def is_enabled(config: configparser.ConfigParser, check_name: str) -> bool:
    # Fallback true = unknown checks always run in full scan
    return config.getboolean("checks", check_name, fallback=True)
