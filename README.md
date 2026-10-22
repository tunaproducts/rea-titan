# ⚡ REA-TITAN: Next-Gen Autonomous Reverse Engineering Suite & Ghidra Orchestrator

[![GitHub Stars](https://img.shields.io/github/stars/tunaproducts/rea-titan?style=social)](https://github.com/tunaproducts/rea-titan)
[![License: TITAN-ETHICS-1.0](https://img.shields.io/badge/License-TITAN--ETHICS--1.0-blue.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Windows%2010%2F11%20%7C%20Kali%20Linux-green.svg)](#installation--setup)
[![Python 3.10+](https://img.shields.io/badge/Python-3.10%2B-cyan.svg)](https://python.org)
[![Ghidra 12+](https://img.shields.io/badge/Ghidra-12.1.4-red.svg)](https://ghidra-sre.org/)
[![Model Context Protocol](https://img.shields.io/badge/MCP-Enabled-purple.svg)](https://modelcontextprotocol.io)

> **REA-TITAN** is an advanced, cross-platform reverse engineering framework and AI agent copilot. It combines **NSA Ghidra 12 Headless Decompilation**, **Sliding-Window Shannon Entropy**, **Checksec**, **Crypto Signature Mining**, **License/Serial Anti-Tamper Heuristics**, and **Model Context Protocol (MCP)** into a single unified terminal suite.

---

## 🚀 Key Features & Capabilities

| Capability | Engine / Integration | Description |
|---|---|---|
| **🤖 Interactive AI RE Copilot** | Built-in Heuristic Context Engine | Interactive terminal assistant that explains decompiled code, identifies key verification routines, and suggests bypasses. |
| **🔑 License & Anti-Tamper Auditor** | "New Bugs" Logic & Timing Analyzer | Uncovers client-side serial checks, anti-debugging tricks (`ptrace`, `IsDebuggerPresent`, `RDTSC`), and non-constant-time timing attack leaks (`strcmp`/`memcmp`). |
| **⚡ Ghidra Headless Core** | NSA Ghidra 12.x + Headless Java Decompiler | Fully automated headless decompilation into clean C-pseudocode, xrefs, prototypes, and callers exported to JSON without GUI. |
| **📊 Shannon Entropy Scanner** | Sliding Window Entropy Engine | Calculates block-level entropy (0.0 - 8.0) to pinpoint packed, compressed, and encrypted sections or hidden shellcode. |
| **🛡️ Dangerous API & Vulnerability Audit** | Automated Binary Security Auditor | Audits binary for hazardous libc calls (`gets`, `strcpy`, `sprintf`, `system`, `popen`) and outputs a Security Score (0-100). |
| **🧩 Fast Native Disassembly** | Capstone 5 Engine | Disassembles raw opcodes or binary offsets in microseconds across x86/x64, ARM, MIPS, and RISC-V. |
| **🔗 ROP Gadget Finder** | Binary Executable Gadget Scanner | Finds common ROP gadgets (`pop rdi; ret`, `pop rsi; ret`, `syscall`) to verify mitigation resilience (ASLR/PIE, Intel CET). |
| **🔍 Binary Triage & Checksec** | Native ELF/PE/Mach-O Parsers | Instant inspection of architectures, endianness, entry points, Stack Canary, NX/DEP, PIE, and RELRO. |
| **🔎 Deep String & Secret Miner** | Regex Intelligence Engine | Mines and classifies URLs, IPs, API tokens (AWS, GitHub, JWT), format strings, and shell command executions. |
| **📦 Hardware & Firmware Unpacker** | Specialized Decoder Modules | Unpacks router configs (e.g., ZTE ZXHN H3600P / H298A Base64 structures) and embedded zlib/gzip streams. |
| **🌐 AI Agent MCP Server** | Model Context Protocol (JSON-RPC) | Connects Cursor, Claude Code, Gemini CLI, or Antigravity agents directly to binary reversing tools over stdio. |
| **🎯 Dynamic Instrument & Pwn** | Frida & Pwntools Generators | Generates ready-to-use Frida interceptor scripts and Pwntools exploit/fuzzing harness boilerplate. |

---

## 🛠️ Installation & Setup

### 🪟 Windows 10 & 11 Setup

1. **Clone the Repository:**
   ```powershell
   git clone https://github.com/tunaproducts/rea-titan.git
   cd rea-titan
   ```

2. **Install Python Dependencies:**
   ```powershell
   pip install -r requirements.txt
   ```

3. **Install Ghidra (Optional for Decompilation):**
   - Extract Ghidra 12.x to `C:\ghidra` (or any preferred folder).
   - REA-TITAN automatically detects `analyzeHeadless.bat`!

4. **Run using PowerShell or CMD:**
   ```powershell
   .\bin\rea-titan.ps1 --help
   ```

---

### 🐧 Kali / Debian / Ubuntu Setup

1. **Clone the Repository:**
   ```bash
   git clone https://github.com/tunaproducts/rea-titan.git
   cd rea-titan
   ```

2. **Install Python Dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

3. **Run using Bash Launcher:**
   ```bash
   ./bin/rea-titan --help
   ```

---

## 💻 CLI Usage Guide

REA-TITAN provides single-command workflows and a cyberpunk terminal UI:

### 1. Interactive AI Reverse Engineering Copilot
```bash
rea-titan copilot /path/to/binary
```
*Launches an interactive prompt (`Titan-Copilot >`). Ask questions like `keys`, `antidebug`, `decompile <func_name>`, `patch`, or `summary`.*

### 2. License Key Verification & Anti-Tamper Audit
```bash
rea-titan keys /path/to/binary
```
*Identifies serial key comparisons, anti-debugging mechanisms (`ptrace`, `IsDebuggerPresent`, `RDTSC`), and non-constant-time timing attack vulnerabilities.*

### 3. Automated Ghidra Headless Decompilation
```bash
# Decompile and display a specific function in terminal:
rea-titan decompile /path/to/target --func verify_license

# Decompile all functions and export AST to JSON:
rea-titan decompile /path/to/target --out decompiled.json
```

### 4. Vulnerability & Dangerous API Security Audit
```bash
rea-titan audit /path/to/binary
```
*Scores the binary (0-100) and details remediation advice for unsafe C functions.*

### 5. Fast Binary Triage & Format Detection
```bash
rea-titan triage /path/to/binary
```

### 6. Security Mitigations (Checksec)
```bash
rea-titan checksec /path/to/binary
```

### 7. Shannon Entropy Scan (Packing & Encryption Detection)
```bash
rea-titan entropy /path/to/binary
```

### 8. Capstone Native Disassembly
```bash
rea-titan disasm /path/to/binary --offset 0x1000 --count 20
```

### 9. ROP Gadget Scanner
```bash
rea-titan rop /path/to/binary
```

### 10. Interactive Colorized Hexdump
```bash
rea-titan hex /path/to/binary --offset 0x0 --length 128
```

### 11. Secret & Endpoint Mining
```bash
rea-titan strings /path/to/binary --min-length 5
```

### 12. Full-Auto Autonomous RE Report
Executes triage, mitigations, entropy, crypto constants, string mining, API vulnerability audit, and compiles an executive markdown report:
```bash
rea-titan auto /path/to/binary --report executive_report.md
```

### 13. AI Agent MCP Server Mode
Integrate REA-TITAN into Cursor, Claude Desktop, or custom AI coding agents:
```bash
rea-titan mcp
```

Add to your `mcp_config.json`:
```json
{
  "mcpServers": {
    "rea-titan": {
      "command": "rea-titan",
      "args": ["mcp"]
    }
  }
}
```

---

## 🏗️ Repository Architecture

```
rea-titan/
├── bin/
│   ├── rea-titan                  # Linux / macOS Bash launcher
│   ├── rea-titan.bat              # Windows Command Prompt launcher
│   └── rea-titan.ps1              # Windows PowerShell launcher
├── rea_titan/
│   ├── cli.py                     # Master CLI entrypoint (Click + Rich TUI)
│   ├── config.py                  # Cross-platform environment & Ghidra detector
│   ├── core/
│   │   ├── assistant.py           # Interactive AI Copilot & Guidance engine
│   │   ├── auditor.py             # Security vulnerability & unsafe API auditor
│   │   ├── binary.py              # ELF, PE, Mach-O, Raw format triage
│   │   ├── disasm.py              # Capstone 5 fast disassembly engine
│   │   ├── entropy.py             # Sliding-window Shannon entropy scanner
│   │   ├── firmware.py            # Hardware config & router firmware unpacker
│   │   ├── license_audit.py       # License check, anti-tamper & anti-debug analyzer
│   │   ├── mitigations.py         # Checksec mitigations inspector (NX, PIE, Canary)
│   │   ├── rop.py                 # ROP gadget scanner
│   │   ├── signatures.py          # Crypto S-Boxes, hashes & packer signatures
│   │   └── strings.py             # Deep string, secret, and endpoint miner
│   ├── ghidra/
│   │   ├── headless.py            # NSA Ghidra analyzeHeadless process manager
│   │   └── scripts/
│   │       └── TitanExportJson.java # Headless Java script: decompile all functions to JSON
│   ├── bridge/
│   │   ├── mcp_server.py          # Model Context Protocol stdio server for AI agents
│   │   ├── dynamic_frida.py       # Frida hook script generator
│   │   └── pwntools_gen.py        # Pwntools exploit skeleton generator
│   └── tui/
│       ├── console.py             # Rich styling, cyberpunk banners, and tables
│       └── hexview.py             # Colorized terminal hexdump viewer
├── requirements.txt               # Python package dependencies
├── setup.py                       # Package installation script
├── LICENSE                        # TITAN-ETHICS-1.0 Ethical Research License
└── README.md                      # Comprehensive project documentation
```

---

## ⚖️ Ethical Research License (TITAN-ETHICS-1.0)

This software is released under the **TITAN-ETHICS-1.0** license, based on the MIT License with mandatory covenants for ethical research and responsible disclosure:

1. **Authorized Use Only:** Must be used solely on authorized targets, educational analysis, defensive engineering, firmware auditing, and malware research.
2. **Anti-Malicious Covenant:** Unauthorized intrusions, weaponized exploits, malware deployment, or unlawful cyber activities are strictly prohibited and terminate all license rights.
3. **Responsible Disclosure:** Any vulnerability, 0-day, or credential discovered using this tool must follow responsible, coordinated disclosure guidelines.

See the complete [LICENSE](LICENSE) file for full legal terms.
