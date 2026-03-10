# claudecode-re-toolkit

Reverse engineering & malware analysis toolkit for [Claude Code](https://claude.com/claude-code) — integrating static analysis, dynamic analysis, and web forensics through Claude Code skills.

## Features

| Skill | Description | Backend |
|-------|-------------|---------|
| **proxy-web** | Safe access to malicious websites with full forensic capture | Docker (Chromium + Playwright) |
| **ghidra-headless** | Automated static analysis with Ghidra (decompile, imports, strings, YARA, CAPA) | Docker (Ghidra 12.0.3) |
| **vmware-sandbox** | Dynamic malware analysis with VMware VM (unpacking, Frida DBI, FakeNet) | VMware Workstation |

## Architecture

```
┌─────────────────────────────────────────────────┐
│                  Claude Code                     │
│              (AI-driven orchestration)           │
├───────────────┬───────────────┬─────────────────┤
│  proxy-web    │ ghidra-headless│ vmware-sandbox  │
│  (Docker)     │  (Docker)     │  (VMware VM)    │
├───────────────┼───────────────┼─────────────────┤
│ • Screenshot  │ • Decompile   │ • Unpacking     │
│ • HTML save   │ • Imports     │ • Frida DBI     │
│ • Downloads   │ • Strings     │ • FakeNet C2    │
│ • VT/MB/TF    │ • YARA/CAPA   │ • PE-sieve      │
│ • AES encrypt │ • IOC extract │ • Memory dump   │
│ • Tor support │ • Classify    │ • x64dbg        │
└───────────────┴───────────────┴─────────────────┘
```

## Quick Start

### Prerequisites

- **Windows 10/11** (Linux/macOS is not officially supported)
- [Claude Code](https://claude.com/claude-code) installed
- Docker Desktop running
- [VMware Workstation Pro](https://www.vmware.com/products/desktop-hypervisor/workstation-and-fusion) (vmware-sandbox skill requires vmrun CLI)
- Go 1.21+
- Python 3.10+

### Setup

```bash
# Clone
git clone https://github.com/<your-username>/claudecode-re-toolkit.git
cd claudecode-re-toolkit

# Environment variables
cp .env.example .env
# Edit .env with your API keys and passwords

# Build proxy-web
cd tools/proxy-web
go build -o proxy-web.exe .
docker build -t proxy-web-browser:latest .
cd ../..

# Start ghidra-headless
cd tools/ghidra-headless
docker compose up -d
cd ../..

# VMware sandbox setup (see docs)
# tools/vmware-sandbox/docs/VM-SETUP.md
```

### Usage with Claude Code

```bash
# Start Claude Code in the repository
claude

# Then use skills:
# "Analyze this URL for malware" → proxy-web
# "Analyze this binary with Ghidra" → ghidra-headless
# "Run dynamic analysis on this packed binary" → vmware-sandbox
```

## Typical Workflow

1. **Web Collection**: Use proxy-web to safely visit malicious URLs and collect artifacts
2. **Static Analysis**: Analyze downloaded binaries with ghidra-headless (YARA, CAPA, decompile)
3. **Dynamic Analysis**: For packed/obfuscated samples, use vmware-sandbox for runtime analysis
4. **Re-analysis**: Analyze unpacked binaries with ghidra-headless for full decompilation

## Security

- All malware downloads are AES-256-CBC encrypted inside Docker containers
- VM dynamic analysis runs in network-isolated (Host-Only) mode
- **Never decrypt malware on the host OS** — always decrypt inside Docker/VM
- Quarantine and output directories are gitignored

## Tool Details

### proxy-web

Go-based CLI tool for safe web forensics:
- Docker-isolated Chromium browser
- Automatic AES-256 encryption of all downloads
- VirusTotal, MalwareBazaar, ThreatFox integration
- Tor proxy support
- Directory listing parser for C2 servers

### ghidra-headless

Docker-based Ghidra automation:
- Full binary analysis (info, imports, exports, strings, functions, xrefs, decompile)
- YARA scanning with signature-base and yara-forge rules
- Mandiant CAPA capability analysis with MITRE ATT&CK mapping
- IOC extraction (IP, domain, URL, hash, registry keys)
- Malware classification (InfoStealer, Ransomware, RAT, Dropper, Loader, Worm)

### vmware-sandbox

VMware Workstation VM automation:
- 3-Level Unpacking System (memdump-racer → TinyTracer → x64dbg)
- Frida DBI with anti-debug bypass and memory dumping
- FakeNet-NG integration for C2 protocol capture
- Network isolation management
- Comprehensive guest tool suite (x64dbg, PE-sieve, HollowsHunter, etc.)

## License

MIT License
