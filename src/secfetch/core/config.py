import configparser
from pathlib import Path

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
# STANDARDIZATION FIX: Updated config keys to match new Title Case check names
kptr_restrict = false        # "Kptr Restrict" -> "kptr_restrict"
dmesg_restrict = false       # "Dmesg Restrict" → "dmesg_restrict"
ptrace_scope = false         # "Ptrace Scope" → "ptrace_scope"
modules_disabled = false     # "Modules Disabled" → "modules_disabled"
unprivileged_bpf = false     # "Unprivileged BPF" → "unprivileged_bpf"
ipv6 = false
# IMPLEMENTATION FIX: Corrected config names to match actual check names
world_writable = false        # "World Writable" → "world_writable"
suid_binaries = false        # "SUID Binaries" -> "suid_binaries"
/tmp_noexec = false          # "/tmp noexec" → "/tmp_noexec"
/tmp_sticky_bit = false      # "/tmp Sticky Bit" → "/tmp_sticky_bit"
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
    """
    Check if a security check is enabled in the configuration.
    CRITICAL BUG FIX: Changed fallback from True to False to fix fastscan behavior.

    - fastscan mode: only runs checks explicitly enabled in config (fallback=False needed)
    - fullscan mode: runs all checks regardless of config (but this function isn't used for fullscan)

    The previous fallback=True caused ALL unknown checks to run in fastscan, breaking the
    entire purpose of having separate fast/full scan modes.
    """
    return config.getboolean("checks", check_name, fallback=False)
