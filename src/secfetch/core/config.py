import configparser
from pathlib import Path

CONFIG_PATH = Path.home() / ".config" / "secfetch" / "checks.conf"

DEFAULT_CONFIG = """
[checks]
# --- fastscan: fast checks, no filesystem traversal ---
# Keys must match: check_name.lower().replace(" ", "_")
aslr = true
secure_boot = true
kernel = true
lockdown = true
firewall_rules = true
open_ports = true
ptrace_scope = true
dmesg_restrict = true
tcp_syn_cookies = true
reverse_path_filter = true

# --- fullscan only: slow or lower priority ---
lsm = false
kptr_restrict = false
modules_disabled = false
unprivileged_bpf = false
ipv6 = false
world_writable = false
suid_binaries = false
/tmp_noexec = false
/tmp_sticky_bit = false
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
    """
    Check if a security check is enabled in the configuration.
    CRITICAL BUG FIX: Changed fallback from True to False to fix fastscan behavior.

    - fastscan mode: only runs checks explicitly enabled in config (fallback=False needed)
    - fullscan mode: runs all checks regardless of config (but this function isn't used for fullscan)

    The previous fallback=True caused ALL unknown checks to run in fastscan, breaking the
    entire purpose of having separate fast/full scan modes.
    """
    return config.getboolean("checks", check_name, fallback=False)
