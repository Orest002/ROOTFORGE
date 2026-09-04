# ROOTFORGE

> **Linux Privilege-Escalation Enumerator** — a fast, dependency-free Bash script that maps the local privesc attack surface of a Linux host and prints a clean, colored, sectioned report.

![Bash](https://img.shields.io/badge/shell-bash-4EAA25?logo=gnubash&logoColor=white)
![License](https://img.shields.io/badge/license-MIT-blue)
![Read--Only](https://img.shields.io/badge/mode-read--only-success)
![Use](https://img.shields.io/badge/authorized%20use-only-red)

ROOTFORGE is an original, single-file enumerator built for CTFs, exam prep (eJPT / OSCP), and **authorized** security assessments. It is intentionally simple and heavily commented so you can read exactly what it does — no obfuscation, no network calls, no surprises.

> **READ-ONLY GUARANTEE:** ROOTFORGE never modifies the target system. It only reads files and runs non-destructive query commands. The single exception is the optional report file you request yourself with `-o`.

---

## Features

- **System & kernel** — `uname -a`, distro from `/etc/os-release`, architecture; informational flag on suspiciously old kernels.
- **User context** — `id` / groups, with loud flags for privesc-relevant groups (`sudo`, `wheel`, `docker`, `lxd`, `disk`, `shadow`).
- **Sudo rights** — non-interactive `sudo -n -l` (never prompts/hangs); highlights `NOPASSWD` rules and GTFOBins-abusable binaries.
- **SUID / SGID binaries** — full-filesystem `find -perm -4000 / -2000`, cross-checked against a built-in ~40-entry GTFOBins watch list with loud match highlighting.
- **Capabilities** — `getcap -r /` when available; flags `cap_setuid`, `cap_sys_admin`, `cap_dac_*`, etc.
- **World-writable & writable root files** — world-writable dirs/files and writable files inside `$PATH` (binary-hijack candidates).
- **Cron jobs** — `/etc/crontab`, `/etc/cron.*`, user crontab; flags world-writable cron scripts.
- **Interesting files** — readable `/etc/shadow`, private SSH keys, shell history, and a **bounded** grep of config paths for `password`.
- **PATH analysis** — writable `$PATH` directories and `.` in `PATH`.
- **Network** — listening ports via `ss -tulpn` with a `netstat` fallback.
- **Quality of life** — ASCII banner, color-coded severity (red / green / yellow), `--no-color`, `-q` quiet mode, `-o` report export (colors stripped in the file). Degrades gracefully when optional tools are missing.

---

## Usage

```bash
chmod +x rootforge.sh
./rootforge.sh                 # colored report to the terminal
./rootforge.sh -o report.txt   # also save a plain-text report
./rootforge.sh -q --no-color   # quiet, no colors (great for logs/pipes)
```

| Option | Description |
| ------ | ----------- |
| `-o FILE` | Also save a color-stripped report to `FILE`. |
| `-q` | Quiet mode: show findings, hide routine OK/info lines. |
| `--no-color` | Disable ANSI colors. |
| `-h`, `--help` | Show help. |
| `-V`, `--version` | Print version. |

---

## Sample output

```
    ____  ____  ____  ______________  ____  ____________
   / __ \/ __ \/ __ \/_  __/ ____/ / / __ \/ ____/ ____/
  / /_/ / / / / / / / / / / /_  / / / /_/ / / __/ __/
 / _, _/ /_/ / /_/ / / / / __/ / /_/ / _, _/ /_/ / /___
/_/ |_|\____/\____/ /_/ /_/    \____/_/ |_|\____/_____/

  Linux Privilege-Escalation Enumerator  v1.0.0
  by Aliasger Fatullayev  -  READ-ONLY, authorized use only

==[ USER CONTEXT ]===============================================
  id: uid=1000(analyst) gid=1000(analyst) groups=1000(analyst),27(sudo),999(docker)
  [!] Member of 'sudo' - can likely run sudo (check sudo section).
  [!] Member of 'docker' - trivial root via container mount. (GTFOBins: docker)

==[ SUDO RIGHTS ]===============================================
  [!] NOPASSWD rule: (root) NOPASSWD: /usr/bin/find
  [!] Sudo rule references GTFOBins binary 'find' - likely escalatable.

==[ SUID / SGID BINARIES ]===============================================
  [!] SUID + GTFOBins: /usr/bin/vim.basic   <== check gtfobins.github.io/gtfobins/vim
      SUID: /usr/bin/passwd

==[ FILE CAPABILITIES ]===============================================
  [!] Dangerous capability: /usr/bin/python3.11 = cap_setuid+ep

==[ INTERESTING FILES ]===============================================
  [!] /etc/shadow is READABLE by current user (crack hashes offline!).
  [!] Private key readable: /home/analyst/.ssh/id_rsa
```

---

## ⚠️ Legal / Ethical Use

ROOTFORGE is provided for **education and authorized security testing only**. Run it **exclusively** on systems you own or have **explicit, written permission** to assess. Unauthorized scanning or access of computer systems is illegal in most jurisdictions. The author accepts no liability for misuse. You are responsible for your actions.

---

## Author

**Əliəsgər Fətullayev** (Aliasger Fatullayev)
Cybersecurity student — offensive security & tooling.
Licensed under the [MIT License](LICENSE).
