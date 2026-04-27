# claudecode-re-toolkit

**English** | [Japanese (日本語)](README_JP.md)

Reverse engineering & malware analysis toolkit for [Claude Code](https://claude.com/claude-code) — integrating static analysis, dynamic analysis, and web forensics through Claude Code skills.

## Features

| Skill | Description | Backend |
|-------|-------------|---------|
| **malware-fetch** | Safe access to malicious websites with full forensic capture, C2 profiling, ClickFix detection, OTX/VT/MB/TF threat intel | Docker (Chromium + Playwright) |
| **ghidra-headless** | Automated static analysis with Ghidra (decompile, imports, strings, YARA, CAPA, .NET decompile), analyzer+reviewer agent team | Docker (Ghidra 12.0.3 + Kali/radare2) |
| **malware-sandbox** | Dynamic malware analysis with VMware VM (unpacking, Frida DBI, FakeNet, DispatchLogger COM monitoring) | VMware Workstation |
| **toolkit-setup** | Interactive setup wizard for .env, Docker builds, YARA/CAPA, and VMware config | — |

## Architecture

```
┌─────────────────────────────────────────────────┐
│                  Claude Code                     │
│              (AI-driven orchestration)           │
├───────────────┬───────────────┬─────────────────┤
│  malware-fetch    │ ghidra-headless│ malware-sandbox  │
│  (Docker)     │  (Docker)     │  (VMware VM)    │
├───────────────┼───────────────┼─────────────────┤
│ • Screenshot  │ • Decompile   │ • Unpacking     │
│ • HTML save   │ • Imports     │ • Frida DBI     │
│ • Downloads   │ • Strings     │ • FakeNet C2    │
│ • VT/MB/TF/OTX│ • YARA/CAPA   │ • PE-sieve      │
│ • AES encrypt │ • IOC extract │ • Memory dump   │
│ • Tor support │ • Classify    │ • x64dbg        │
│ • C2 profiling│ • .NET decomp │ • DispatchLogger │
│ • ClickFix    │ • Agent team  │ • COM monitor   │
└───────────────┴───────────────┴─────────────────┘
```

## Quick Start

### Prerequisites

- **Windows 10/11** (Linux/macOS is not officially supported)
- [Claude Code](https://claude.com/claude-code) installed
- Docker Desktop running
- [VMware Workstation Pro](https://www.vmware.com/products/desktop-hypervisor/workstation-and-fusion) (malware-sandbox skill requires vmrun CLI)
- Go 1.21+
- Python 3.10+

### Setup

#### Automated (Recommended)

```bash
git clone https://github.com/HiyokoSauna37/claudecode-re-toolkit.git
cd claudecode-re-toolkit
claude
# Then say: "setup" or "/toolkit-setup"
```

The **toolkit-setup** skill guides you through the entire setup interactively — .env creation, Docker image builds, YARA/CAPA installation, and VMware configuration. Choose between an interactive wizard (step-by-step) or batch mode (plan-then-execute).

#### Manual

```bash
# Clone
git clone https://github.com/HiyokoSauna37/claudecode-re-toolkit.git
cd claudecode-re-toolkit

# Environment variables
cp .env.example .env
# Edit .env with your API keys and passwords

# Build Docker images
docker build -t malware-fetch-browser:latest tools/malware-fetch/
docker compose -f tools/ghidra-headless/docker-compose.yml up -d

# VMware sandbox setup (see docs)
# tools/malware-sandbox/docs/VM-SETUP.md
```

Pre-built Windows binaries (malware-fetch.exe, vmrun-wrapper.exe, etc.) are included in the repository. No Go build required.

### Environment Variables (.env)

Copy `.env.example` to `.env` and configure:

| Variable | Description | Required for |
|----------|-------------|-------------|
| `QUARANTINE_PASSWORD` | Password for AES-256-CBC encryption of downloaded malware files. Set any strong password. | malware-fetch |
| `VIRUSTOTAL_API_KEY` | VirusTotal API key ([free tier](https://www.virustotal.com/gui/join-us) available). Used for hash lookups and behavior analysis. | malware-fetch (`check` / `behavior` / `lookup`) |
| `ABUSECH_AUTH_KEY` | [abuse.ch](https://auth.abuse.ch/) API key for MalwareBazaar / ThreatFox search. Optional — works without it but with rate limits. | malware-fetch (`bazaar` / `threatfox`, optional) |
| `VMRUN_PATH` | Full path to `vmrun.exe`. Example: `C:\Program Files (x86)\VMware\VMware Workstation\vmrun.exe` | malware-sandbox |
| `VM_VMX_PATH` | Full path to the VM's `.vmx` file. Example: `C:\VMs\Win10\Win10.vmx` | malware-sandbox |
| `VM_GUEST_USER` | Guest OS login username | malware-sandbox |
| `VM_GUEST_PASS` | Guest OS login password | malware-sandbox |
| `VM_GUEST_PROFILE` | Guest OS user profile directory. Example: `C:\Users\analyst` | malware-sandbox |
| `VM_SNAPSHOT` | Clean snapshot name to revert to after analysis (default: `clean_with_tools`) | malware-sandbox (optional) |
| `VMRUN_TIMEOUT` | Timeout in seconds for vmrun commands (default: `30`) | malware-sandbox (optional) |

> **Note:** malware-fetch and ghidra-headless only require `QUARANTINE_PASSWORD` and optionally the API keys. The `VM_*` variables are only needed if you use malware-sandbox.

### Usage with Claude Code

```bash
# Start Claude Code in the repository
claude

# Then use skills:
# "Analyze this URL for malware" → malware-fetch
# "Analyze this binary with Ghidra" → ghidra-headless
# "Run dynamic analysis on this packed binary" → malware-sandbox
```

## GUI Dashboard (Experimental)

A web-based GUI dashboard is available as an experimental frontend for the toolkit. It provides a chat interface powered by Claude Code subprocess, with real-time tool activity monitoring, quarantine file browser, report viewer, and more.

![GUI Dashboard](docs/gui-dashboard.png)
![Analysis in Progress](docs/gui-analysis.png)

```bash
cd tools/gui-prototype
pip install fastapi uvicorn python-dotenv pyyaml
python server.py
# Open http://localhost:8765
```

**Features:**
- Chat interface with Claude Code (streaming, session management)
- Quarantine file browser with drag & drop analysis
- Report viewer with Markdown rendering
- Tool activity log with per-tool color coding
- VM Live View (VMware screenshot streaming)
- Pipeline indicator (Triage → Static → Dynamic → Report)
- Command palette (Ctrl+K), keyboard shortcuts
- Multiple themes (Default, Claude, Cyber, Arctic, Amethyst, Light)

> **Note:** This is a prototype under active development. Some features may be unstable.

## Typical Workflow

1. **Web Collection**: Use malware-fetch to safely visit malicious URLs and collect artifacts
2. **Static Analysis**: Analyze downloaded binaries with ghidra-headless (YARA, CAPA, decompile)
3. **Dynamic Analysis**: For packed/obfuscated samples, use malware-sandbox for runtime analysis
4. **Re-analysis**: Analyze unpacked binaries with ghidra-headless for full decompilation

## Security

- All malware downloads are AES-256-CBC encrypted inside Docker containers
- VM dynamic analysis runs in network-isolated (Host-Only) mode
- **Never decrypt malware on the host OS** — always decrypt inside Docker/VM
- Quarantine and output directories are gitignored

## Tool Details

### malware-fetch

Go-based CLI tool for safe web forensics:
- Docker-isolated Chromium browser
- Automatic AES-256 encryption of all downloads (including `fetch` output, for Defender evasion)
- VirusTotal, MalwareBazaar, ThreatFox, OTX integration
- C2 auto-profiling (VT + ThreatFox + OTX + Passive DNS + port scan)
- Cluster-wide C2 profiling via `c2cluster.py` (ThreatFox tag expansion, fingerprint-based hunting)
- Threat-intel tool suite under `tools/malware-fetch/intel/` — `c2hunt`, `threatfeed`, `iocminer`, `loghunter`, `intel` dispatcher, `hunt-report.exe` (Go aggregator)
- ClickFix detection and JS deobfuscation (`js_deobfuscate.py --url` for disk-less analysis)
- ClearFake Polygon-blockchain C2 decoder (`clearfake_decode.py`)
- Network log classification (BLOCKCHAIN_RPC, C2_API, TRACKER, etc.)
- Batch domain probing for large-scale IOC triage
- Preflight check for Docker daemon and ThreatFox `--limit N` support (up to 1000)
- Tor proxy support
- Directory listing parser for C2 servers

### ghidra-headless

Docker-based Ghidra automation:
- Full binary analysis (info, imports, exports, strings, functions, xrefs, decompile)
- .NET binary decompilation via ILSpy CLI (dotnet-decompile, dotnet-metadata, dotnet-types)
- PE Triage (Phase 0) with packer detection and entropy analysis
- YARA scanning with signature-base and yara-forge rules
- Mandiant CAPA capability analysis with MITRE ATT&CK mapping
- IOC extraction (IP, domain, URL, hash, registry keys)
- Malware classification (InfoStealer, Ransomware, RAT, Dropper, Loader, Worm)
- Analyzer + Reviewer agent team for quality-assured analysis sessions
- Kali Linux container with radare2 for quick triage, entropy analysis, crypto detection, and binary diffing
- Helper scripts: `lnk-parser.py` (LNK triage), `pe-encrypt.py` (.enc.gz generator for VM transfer), `chunk-extract.py` (.rdata embedded binary extraction)
- Automatic command logging — every `ghidra.sh` invocation appends to `tools/ghidra-headless/logs/YYYYMMDD_<target>.md`; review with `ghidra.sh log-show <binary>`

### malware-sandbox

VMware Workstation VM automation:
- One-command `analyze` workflow that auto-handles snapshot revert, Host-Only network isolation, malware copy, pre/post snapshots, HollowsHunter scan, and final revert (no manual `start` / `net-isolate` needed)
- 3-Level Unpacking System (memdump-racer → TinyTracer → x64dbg)
- Frida DBI with anti-debug bypass and memory dumping (with preflight check for guest Frida install)
- DispatchLogger COM monitoring for script-based malware (VBS, JS, HTA, PowerShell, Office macros)
- FakeNet-NG integration for C2 protocol capture
- Network isolation management
- Comprehensive guest tool suite (x64dbg, PE-sieve, HollowsHunter, etc.)
- Automatic `.enc.gz` quarantine decryption inside the VM (host never touches raw malware)
- BOM-less UTF-8 script deployment and `Start-Process`-based persistent tool launching to avoid vmrun hangs

## License

MIT License
