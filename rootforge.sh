#!/usr/bin/env bash
#
# ============================================================================
#  ROOTFORGE  -  Linux Privilege-Escalation Enumerator
# ============================================================================
#  Author : Aliasger Fatullayev (Əliəsgər Fətullayev)
#  License: MIT (2026)
#  Version: 1.0.0
#
#  WHAT IT DOES
#    Enumerates the LOCAL privilege-escalation attack surface of a Linux host
#    and prints a clean, colored, sectioned report. Built for CTFs, exam prep
#    (eJPT/OSCP), and authorized security assessments.
#
#  READ-ONLY GUARANTEE
#    This script NEVER modifies the system. It only reads files, lists
#    metadata, and runs non-destructive query commands (id, uname, find,
#    getcap, ss, sudo -n -l, etc.). It writes nothing outside of an optional
#    report file that YOU request with -o. No files are created, deleted,
#    chmod'd, or executed on your behalf.
#
#  DEPENDENCIES
#    Pure bash + coreutils/find/grep. Optional helpers (getcap, ss, netstat,
#    sudo) are used only if present; the script degrades gracefully otherwise.
#
#  ETHICAL USE
#    Run ONLY on systems you own or are explicitly authorized to assess.
# ============================================================================

# `set -u` catches unset-variable bugs. We deliberately do NOT use `set -e`
# because many enumeration commands are expected to "fail" (missing tools,
# permission-denied) and that must not abort the whole run.
set -u

# ----------------------------------------------------------------------------
#  Globals / configuration
# ----------------------------------------------------------------------------
VERSION="1.0.0"
USE_COLOR=1          # 1 = colored output, 0 = plain (toggled by --no-color)
QUIET=0              # 1 = quiet mode (suppress OK/info noise, show findings)
OUTFILE=""           # optional path to also save a (color-stripped) report
KERNEL_OLD_YEAR=2018 # kernels older than roughly this are flagged informationally

# GTFOBins-style watch list: binaries that are commonly abusable when they
# carry the SUID/SGID bit or appear in a sudo rule. This is a curated subset;
# see https://gtfobins.github.io for the full, authoritative catalog.
GTFOBINS="nmap vim vi nano awk gawk find bash sh dash zsh python python2 python3 \
perl ruby lua less more man cp mv tar zip unzip gzip gdb make nc ncat socat \
tee dd env ftp scp rsync wget curl base64 xxd ed emacs ex view flock time \
strace ltrace nohup timeout stdbuf setarch busybox docker lxc pkexec systemctl \
mount umount crontab tcpdump journalctl git ssh sudo openssl"

# ----------------------------------------------------------------------------
#  Color helpers
# ----------------------------------------------------------------------------
init_colors() {
    if [ "$USE_COLOR" -eq 1 ]; then
        C_RED="$(printf '\033[1;31m')"     # likely vuln / high interest
        C_GREEN="$(printf '\033[1;32m')"   # looks fine
        C_YELLOW="$(printf '\033[1;33m')"  # informational
        C_BLUE="$(printf '\033[1;34m')"    # section headers
        C_CYAN="$(printf '\033[1;36m')"
        C_DIM="$(printf '\033[2m')"
        C_RST="$(printf '\033[0m')"
    else
        C_RED=""; C_GREEN=""; C_YELLOW=""; C_BLUE=""; C_CYAN=""; C_DIM=""; C_RST=""
    fi
}

# out(): central print function. Everything goes through here so we can both
# print to the terminal AND (optionally) append a color-stripped copy to the
# report file. Uses a sed pass to remove ANSI escapes for the file.
out() {
    printf '%s\n' "$*"
    if [ -n "$OUTFILE" ]; then
        printf '%s\n' "$*" | sed -r 's/\x1b\[[0-9;]*m//g' >> "$OUTFILE"
    fi
}

# Convenience wrappers for severity-tagged lines.
finding() { out "  ${C_RED}[!]${C_RST} $*"; }          # red = notable / risky
ok()      { [ "$QUIET" -eq 1 ] || out "  ${C_GREEN}[+]${C_RST} $*"; }
info()    { [ "$QUIET" -eq 1 ] || out "  ${C_YELLOW}[*]${C_RST} $*"; }
plain()   { out "      $*"; }

section() {
    out ""
    out "${C_BLUE}==[ $* ]===============================================${C_RST}"
}

have() { command -v "$1" >/dev/null 2>&1; }  # is a command available?

# ----------------------------------------------------------------------------
#  Banner
# ----------------------------------------------------------------------------
banner() {
    [ "$QUIET" -eq 1 ] && return 0
    out "${C_CYAN}"
    out '    ____  ____  ____  ______________  ____  ____________'
    out '   / __ \/ __ \/ __ \/_  __/ ____/ / / __ \/ ____/ ____/'
    out '  / /_/ / / / / / / / / / / /_  / / / /_/ / / __/ __/   '
    out ' / _, _/ /_/ / /_/ / / / / __/ / /_/ / _, _/ /_/ / /___ '
    out '/_/ |_|\____/\____/ /_/ /_/    \____/_/ |_|\____/_____/ '
    out "${C_RST}"
    out "  ${C_DIM}Linux Privilege-Escalation Enumerator  v${VERSION}${C_RST}"
    out "  ${C_DIM}by Aliasger Fatullayev  -  READ-ONLY, authorized use only${C_RST}"
    out ""
}

# ----------------------------------------------------------------------------
#  SECTION: System / kernel information
# ----------------------------------------------------------------------------
check_system() {
    section "SYSTEM & KERNEL"
    out "  ${C_CYAN}uname:${C_RST} $(uname -a 2>/dev/null)"

    local arch; arch="$(uname -m 2>/dev/null)"
    out "  ${C_CYAN}arch :${C_RST} ${arch:-unknown}"

    if [ -r /etc/os-release ]; then
        # shellcheck disable=SC1091
        . /etc/os-release 2>/dev/null
        out "  ${C_CYAN}distro:${C_RST} ${PRETTY_NAME:-unknown}"
    elif [ -r /etc/issue ]; then
        out "  ${C_CYAN}distro:${C_RST} $(head -n1 /etc/issue 2>/dev/null)"
    fi

    # Informational only: try to spot an old kernel build date. We never claim
    # a specific CVE; we just nudge the analyst to check kernel exploits.
    local kver kdate kyear
    kver="$(uname -r 2>/dev/null)"
    kdate="$(uname -v 2>/dev/null)"
    kyear="$(printf '%s' "$kdate" | grep -oE '20[0-9]{2}' | tail -n1)"
    if [ -n "$kyear" ] && [ "$kyear" -lt "$KERNEL_OLD_YEAR" ] 2>/dev/null; then
        finding "Kernel build looks old ($kyear). Check kernel-exploit databases for $kver."
    else
        ok "Kernel $kver (build year: ${kyear:-unknown})"
    fi
}

# ----------------------------------------------------------------------------
#  SECTION: Current user context
# ----------------------------------------------------------------------------
check_user() {
    section "USER CONTEXT"
    out "  ${C_CYAN}id:${C_RST} $(id 2>/dev/null)"
    out "  ${C_CYAN}whoami:${C_RST} $(whoami 2>/dev/null)  ${C_DIM}(uid=$(id -u 2>/dev/null))${C_RST}"

    if [ "$(id -u 2>/dev/null)" = "0" ]; then
        info "You are already root - no escalation needed."
    fi

    # Privesc-relevant group memberships.
    local groups; groups="$(id -Gn 2>/dev/null)"
    for g in sudo wheel admin docker lxd disk video adm shadow; do
        case " $groups " in
            *" $g "*)
                case "$g" in
                    sudo|wheel|admin)
                        finding "Member of '$g' - can likely run sudo (check sudo section)." ;;
                    docker)
                        finding "Member of 'docker' - trivial root via container mount. (GTFOBins: docker)" ;;
                    lxd)
                        finding "Member of 'lxd' - classic root via privileged container image." ;;
                    disk)
                        finding "Member of 'disk' - raw block-device read/write => read /etc/shadow, write files." ;;
                    shadow)
                        finding "Member of 'shadow' - can read /etc/shadow (crack hashes offline)." ;;
                    *)
                        info "Member of '$g' (potentially useful group)." ;;
                esac ;;
        esac
    done
}

# ----------------------------------------------------------------------------
#  SECTION: Sudo rights (non-interactive, never prompts for a password)
# ----------------------------------------------------------------------------
check_sudo() {
    section "SUDO RIGHTS"
    if ! have sudo; then
        info "sudo not installed."
        return 0
    fi

    # -n = non-interactive: if a password would be required, sudo just fails
    # instead of hanging on a prompt. This keeps the scan fast and read-only.
    local sudo_out
    sudo_out="$(sudo -n -l 2>/dev/null)"
    if [ -z "$sudo_out" ]; then
        info "No passwordless sudo rights (or a password is required)."
        return 0
    fi

    out "$sudo_out" | while IFS= read -r line; do
        if printf '%s' "$line" | grep -qi 'NOPASSWD'; then
            finding "NOPASSWD rule: $line"
        else
            plain "$line"
        fi
    done

    # Cross-reference any binaries mentioned with the GTFOBins watch list.
    for bin in $GTFOBINS; do
        if printf '%s' "$sudo_out" | grep -qwi "$bin"; then
            finding "Sudo rule references GTFOBins binary '$bin' - likely escalatable."
        fi
    done
}

# ----------------------------------------------------------------------------
#  Helper: does this basename appear in the GTFOBins watch list?
# ----------------------------------------------------------------------------
is_gtfobin() {
    local name="$1"
    case " $GTFOBINS " in *" $name "*) return 0 ;; *) return 1 ;; esac
}

# ----------------------------------------------------------------------------
#  SECTION: SUID / SGID binaries
# ----------------------------------------------------------------------------
check_suid_sgid() {
    section "SUID / SGID BINARIES"

    info "Scanning filesystem for SUID (-4000) binaries..."
    # -perm -4000 : SUID bit set. Errors (permission denied) are discarded.
    find / -xdev -type f -perm -4000 2>/dev/null | while IFS= read -r f; do
        local base; base="$(basename "$f")"
        if is_gtfobin "$base"; then
            finding "SUID + GTFOBins: $f   <== check gtfobins.github.io/gtfobins/$base"
        else
            plain "SUID: $f"
        fi
    done

    info "Scanning filesystem for SGID (-2000) binaries..."
    find / -xdev -type f -perm -2000 2>/dev/null | while IFS= read -r f; do
        local base; base="$(basename "$f")"
        if is_gtfobin "$base"; then
            finding "SGID + GTFOBins: $f   <== check gtfobins.github.io/gtfobins/$base"
        else
            plain "SGID: $f"
        fi
    done
}

# ----------------------------------------------------------------------------
#  SECTION: File capabilities
# ----------------------------------------------------------------------------
check_capabilities() {
    section "FILE CAPABILITIES"
    if ! have getcap; then
        info "getcap not available (libcap not installed) - skipping."
        return 0
    fi
    local caps; caps="$(getcap -r / 2>/dev/null)"
    if [ -z "$caps" ]; then
        ok "No file capabilities found."
        return 0
    fi
    printf '%s\n' "$caps" | while IFS= read -r line; do
        # cap_setuid / cap_setgid / cap_dac* / cap_sys_admin are the juicy ones.
        if printf '%s' "$line" | grep -qiE 'cap_setuid|cap_setgid|cap_dac_(override|read_search)|cap_sys_admin|cap_sys_ptrace'; then
            finding "Dangerous capability: $line"
        else
            plain "$line"
        fi
    done
}

# ----------------------------------------------------------------------------
#  SECTION: World-writable files/dirs + writable root-owned files in PATH
# ----------------------------------------------------------------------------
check_writable() {
    section "WORLD-WRITABLE & WRITABLE ROOT FILES"

    info "World-writable directories (excluding sticky-bit temp dirs)..."
    # -perm -0002 : world-writable. We exclude the sticky bit (+t, -1000) since
    # /tmp-style dirs are expected to be world-writable and are lower interest.
    find / -xdev -type d -perm -0002 ! -perm -1000 2>/dev/null | head -n 40 \
        | while IFS= read -r d; do finding "World-writable dir: $d"; done

    info "World-writable files owned by root..."
    find / -xdev -type f -perm -0002 -uid 0 2>/dev/null | head -n 40 \
        | while IFS= read -r f; do finding "World-writable root file: $f"; done

    info "Writable files in PATH directories (hijack candidates)..."
    local IFS=:
    for dir in $PATH; do
        [ -d "$dir" ] || continue
        # -writable finds anything the current user can modify -> binary hijack.
        find "$dir" -maxdepth 1 -type f -writable 2>/dev/null \
            | while IFS= read -r f; do finding "Writable PATH file: $f"; done
    done
    unset IFS
}

# ----------------------------------------------------------------------------
#  SECTION: Cron jobs
# ----------------------------------------------------------------------------
check_cron() {
    section "CRON JOBS"

    for f in /etc/crontab /etc/cron.d/*; do
        [ -r "$f" ] || continue
        plain "${C_CYAN}$f${C_RST}"
        grep -vE '^\s*#|^\s*$' "$f" 2>/dev/null | while IFS= read -r line; do
            plain "  $line"
        done
    done

    # Flag any cron-referenced script that is world-writable (attacker-modifiable).
    info "Checking cron directories for world-writable scripts..."
    for d in /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly /etc/cron.d; do
        [ -d "$d" ] || continue
        find "$d" -maxdepth 1 -type f -perm -0002 2>/dev/null \
            | while IFS= read -r f; do finding "World-writable cron script: $f"; done
    done

    # User crontab (only our own, read-only listing).
    if have crontab; then
        local uc; uc="$(crontab -l 2>/dev/null)"
        [ -n "$uc" ] && { info "Current user's crontab:"; printf '%s\n' "$uc" | while IFS= read -r l; do plain "  $l"; done; }
    fi
}

# ----------------------------------------------------------------------------
#  SECTION: Interesting / sensitive files
# ----------------------------------------------------------------------------
check_interesting() {
    section "INTERESTING FILES"

    # Readable /etc/shadow is a jackpot.
    if [ -r /etc/shadow ]; then
        finding "/etc/shadow is READABLE by current user (crack hashes offline!)."
    else
        ok "/etc/shadow not readable."
    fi

    # Backup shadow files sometimes left world-readable.
    for f in /etc/shadow- /var/backups/shadow.bak /etc/passwd-; do
        [ -r "$f" ] && finding "Readable sensitive backup: $f"
    done

    info "Searching for private SSH keys in common locations..."
    for d in /home /root /etc/ssh; do
        [ -d "$d" ] || continue
        find "$d" -maxdepth 3 -type f \( -name 'id_rsa' -o -name 'id_dsa' \
            -o -name 'id_ecdsa' -o -name 'id_ed25519' -o -name '*.pem' \) 2>/dev/null \
            | while IFS= read -r k; do
                if grep -qi 'PRIVATE KEY' "$k" 2>/dev/null; then
                    finding "Private key readable: $k"
                fi
            done
    done

    info "Shell history files (may contain passwords/tokens)..."
    for h in /root/.bash_history /home/*/.bash_history /home/*/.zsh_history; do
        [ -r "$h" ] && finding "Readable history: $h"
    done

    info "Grepping common config paths for 'password' (bounded)..."
    # Bounded search: fixed dirs, capped result count, quiet on errors, so this
    # never turns into a full-disk grep that hangs the run.
    grep -rniI --include='*.conf' --include='*.cnf' --include='*.ini' \
        --include='*.env' --include='*.yml' --include='*.yaml' --include='*.php' \
        'password' /etc /var/www /opt 2>/dev/null | head -n 20 \
        | while IFS= read -r line; do plain "$line"; done
}

# ----------------------------------------------------------------------------
#  SECTION: PATH analysis
# ----------------------------------------------------------------------------
check_path() {
    section "PATH ANALYSIS"
    out "  ${C_CYAN}PATH=${C_RST}$PATH"

    case ":$PATH:" in
        *:.:*|*::*)
            finding "'.' (current dir) is in PATH - relative binary hijacking risk." ;;
        *)
            ok "'.' is not in PATH." ;;
    esac

    local IFS=:
    for dir in $PATH; do
        [ -z "$dir" ] && continue
        if [ -d "$dir" ] && [ -w "$dir" ]; then
            finding "Writable PATH directory: $dir (drop a malicious binary here)."
        fi
    done
    unset IFS
}

# ----------------------------------------------------------------------------
#  SECTION: Network / listening ports
# ----------------------------------------------------------------------------
check_network() {
    section "NETWORK (listening services)"
    if have ss; then
        ss -tulpn 2>/dev/null | while IFS= read -r l; do plain "$l"; done
    elif have netstat; then
        netstat -tulpn 2>/dev/null | while IFS= read -r l; do plain "$l"; done
    else
        info "Neither 'ss' nor 'netstat' available - cannot list ports."
    fi
    info "Locally-bound services (127.0.0.1) are often unauthenticated - worth probing."
}

# ----------------------------------------------------------------------------
#  Usage / argument parsing
# ----------------------------------------------------------------------------
usage() {
    cat <<EOF
ROOTFORGE v${VERSION} - Linux Privilege-Escalation Enumerator (READ-ONLY)

Usage: ./rootforge.sh [options]

Options:
  -o FILE       Also save a plain-text (color-stripped) report to FILE.
  -q            Quiet mode: show findings, hide routine OK/info noise.
  --no-color    Disable ANSI colors.
  -h, --help    Show this help and exit.
  -V, --version Print version and exit.

Run ONLY on systems you own or are authorized to assess.
EOF
}

parse_args() {
    while [ "$#" -gt 0 ]; do
        case "$1" in
            -o) shift; OUTFILE="${1:-}"; [ -z "$OUTFILE" ] && { echo "-o requires a filename" >&2; exit 2; } ;;
            -q) QUIET=1 ;;
            --no-color) USE_COLOR=0 ;;
            -h|--help) usage; exit 0 ;;
            -V|--version) echo "ROOTFORGE v${VERSION}"; exit 0 ;;
            *) echo "Unknown option: $1" >&2; usage; exit 2 ;;
        esac
        shift
    done
}

# ----------------------------------------------------------------------------
#  Main
# ----------------------------------------------------------------------------
main() {
    parse_args "$@"
    init_colors

    # Truncate/prepare the report file if requested (this is the ONLY file we
    # ever write to, and only because the user explicitly asked with -o).
    if [ -n "$OUTFILE" ]; then
        : > "$OUTFILE" 2>/dev/null || { echo "Cannot write to $OUTFILE" >&2; exit 1; }
    fi

    banner
    out "${C_DIM}Scan started: $(date 2>/dev/null)${C_RST}"

    check_system
    check_user
    check_sudo
    check_suid_sgid
    check_capabilities
    check_writable
    check_cron
    check_interesting
    check_path
    check_network

    section "DONE"
    ok "Enumeration complete. Review ${C_RED}[!]${C_RST} lines first - those are the highest-value leads."
    [ -n "$OUTFILE" ] && out "  ${C_GREEN}[+]${C_RST} Report saved to: $OUTFILE"
}

main "$@"
