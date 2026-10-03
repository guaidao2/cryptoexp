"""Terminal output helpers (colors, banner, section headers). English-first."""

import sys


class Colors:
    RED = '\033[1;31m'
    GREEN = '\033[1;32m'
    YELLOW = '\033[1;33m'
    BLUE = '\033[1;34m'
    PURPLE = '\033[1;35m'
    CYAN = '\033[1;36m'
    BOLD = '\033[1m'
    END = '\033[0m'


def _supports_color() -> bool:
    return sys.stdout.isatty()


def _c(text: str, color: str) -> str:
    return f"{color}{text}{Colors.END}" if _supports_color() else text


def print_banner():
    """Banner: plain ASCII on purpose.

    The previous banner spelled the old project name in figlet art. Hand-kerned
    figlet glyphs do not survive a rename (the letters read "cryptokit" long after
    the package was called something else) and they smear on terminals without the
    font's bearings, so the banner is text now: it cannot go stale or misalign.
    """
    rule = "=" * 62
    print(_c("\n".join([
        rule,
        "  cryptoexp - dependency-free crypto toolkit",
        "  CTF solving | security assessment | research",
        rule,
    ]), Colors.CYAN))


def print_info(msg: str):
    print(_c(f"[*] {msg}", Colors.CYAN))


def print_success(msg: str):
    print(_c(f"[+] {msg}", Colors.GREEN))


def print_warning(msg: str):
    print(_c(f"[!] {msg}", Colors.YELLOW))


def print_error(msg: str):
    print(_c(f"[-] {msg}", Colors.RED))


def print_section_header(title: str):
    line = "-" * max(8, 46 - len(title))
    print()
    print(_c(f"-- {title} {line}", Colors.BOLD))


def print_field(label: str, value):
    print(f"  {label:<14} {value}")
