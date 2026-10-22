# ⚡ REA-TITAN: Next-Gen Autonomous Reverse Engineering Suite & Ghidra Orchestrator

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/Python-3.10%2B-cyan.svg)](https://python.org)
[![Ghidra 12+](https://img.shields.io/badge/Ghidra-12.1.4-red.svg)](https://ghidra-sre.org/)
[![Model Context Protocol](https://img.shields.io/badge/MCP-Enabled-purple.svg)](https://modelcontextprotocol.io)

> **REA-TITAN** bridges the gap between state-of-the-art AI Agent Protocols (**REA / Model Context Protocol**) and native binary analysis engines (**NSA Ghidra Headless, Checksec, Sliding Shannon Entropy, Crypto Signature Mining, and Hardware/Firmware Unpackers**). 

---

## 🚀 Key Features

| Capability | Engine / Integration | Description |
|---|---|---|
| **Binary Triage** | Native Struct / ELF & PE Parsers | Instant inspection of architectures (x86/x64, ARM, MIPS, RISC-V), endianness, bitness, headers, and symbol tables. |
| **Ghidra Headless Core** | NSA Ghidra 12.x + Java Decomp Script | Fully automated headless decompilation into clean C-pseudocode, xrefs, prototypes, and callers export to JSON. |
| **Shannon Entropy Scanner** | Sliding Window Entropy Engine | Calculates block-level entropy (0.0 - 8.0) to pinpoint packed, compressed, and encrypted sections or hidden shellcode. |
| **Crypto & Packer Detection** | S-Box & Constant Fingerprinting | Identifies AES S-Boxes, SHA-256 / MD5 constants, ChaCha20 patterns, UPX, PyInstaller, Go, and Rust runtimes. |
| **Checksec & Mitigations** | Security Mitigations Inspector | Checks Stack Canary, NX/DEP, PIE/ASLR, Full/Partial RELRO, and Fortified symbols. |
| **Deep String & Secret Miner** | Regex Engine | Extracts and groups URLs, IPv4/IPv6, API tokens (AWS, GitHub, JWT), format strings, and shell command executions. |
| **Hardware & Firmware Unpacker** | Specialized Decode Modules | Automatically unpacks router configs (e.g., ZTE ZXHN H3600P / H298A Base64 structures) and zlib streams. |
| **AI Agent MCP Server** | Model Context Protocol (JSON-RPC) | Allows Claude Code, Cursor, Gemini CLI, or Antigravity agents to trigger autonomous reverse-engineering via tools. |
| **Dynamic Instrument & Pwn** | Frida & Pwntools Generators | Generates ready-to-use Frida interceptor scripts and Pwntools exploit/fuzzing harness boilerplate. |

---

## 🛠️ Installation & Setup

### 1. Requirements
- Linux (Debian, Ubuntu, Kali, Arch)
- Python 3.10+
- OpenJDK 21+ (`sudo apt install openjdk-21-jdk`)
- Ghidra 12.x (Automatically detected at `~/ghidra_12.1.4_PUBLIC` or via `$GHIDRA_HOME`)

### 2. Quick Setup
```bash
git clone https://github.com/your-username/rea-titan.git
cd rea-titan
pip install -e .
```

---

## 💻 CLI Usage

REA-TITAN provides a cyberpunk terminal UI with rich styling and single-command workflows:

### 1. Fast Binary Triage
```bash
rea-titan triage /bin/ls
```

### 2. Security Mitigations (Checksec)
```bash
rea-titan checksec /path/to/target
```

### 3. Shannon Entropy Scan
```bash
rea-titan entropy firmware.bin
```

### 4. Secret & String Mining
```bash
rea-titan strings sample.exe --min-length 6
```

### 5. Cryptographic Algorithm Fingerprinting
```bash
rea-titan crypto /path/to/binary
```

### 6. Automated Ghidra Headless Decompilation
```bash
# Decompile all functions and dump to JSON:
rea-titan decompile /path/to/binary --out decompiled.json

# Decompile and display a specific function in terminal:
rea-titan decompile /path/to/binary --func verify_license
```

### 7. Güvenlik ve Tehlikeli C API Denetimi (Audit)
```bash
rea-titan audit /path/to/binary
```
*Tüm libc çağrılarını tarar; `gets`, `strcpy`, `sprintf`, `system` gibi zafiyet kaynağı fonksiyonları risk derecelerine (CRITICAL, HIGH, MEDIUM) ve iyileştirme tavsiyelerine göre puanlar.*

### 8. Capstone Hızlı Disassembly
```bash
rea-titan disasm /path/to/binary --offset 0x1000 --count 20
```

### 9. ROP Gadget Taraması (Savunma & Mitigasyon Testi)
```bash
rea-titan rop /path/to/binary
```
*Bellek korumalarının (ASLR/PIE, Intel CET, Shadow Stack) etkinliğini doğrulamak için `ret`, `pop rdi`, `syscall` gadget'larını listeler.*

### 10. İnteraktif Renkli Hexdump
```bash
rea-titan hex /path/to/binary --offset 0x0 --length 128
```

### 11. Dinamik Enstrümantasyon (Frida Hook)
```bash
rea-titan frida target_binary 0x1234 --args-count 4
```

### 12. Pwntools Güvenlik Koşum İskeleti
```bash
rea-titan pwn /path/to/binary
```

### 13. Full-Auto Otonom RE & Güvenlik Raporu
Triage, Checksec, Entropi, Kripto İmzaları, Stringler, API Güvenlik Skoru ve Zafiyet Analizini birleştirip tam teşekküllü bir Markdown denetim raporu üretir:
```bash
rea-titan auto target_binary --report guvenlik_analiz_raporu.md
```

### 14. Yapay Zeka Ajanları için MCP Sunucusu (Model Context Protocol)
Cursor, Claude Desktop, Antigravity veya özel LLM ajanlarına tersine mühendislik yetenekleri bağlar:
```bash
rea-titan mcp
```

---

## ⚖️ Etik Araştırma ve Sorumlu Kullanım Sözleşmesi (Ethical Covenant)

Bu proje **TITAN-ETHICS-1.0** lisansı altında dağıtılmaktadır. 
- Yalnızca izinli güvenlik testleri, savunma mühendisliği, firmware denetimi, akademik araştırma ve kötü amaçlı yazılım analizleri için kullanılabilir.
- Yetkisiz sistem sızmaları, zararlı yazılım geliştirme veya yasa dışı faaliyetlerde kullanılması kesinlikle yasaktır ve lisans ihlali teşkil eder.
- Tespit edilen sıfır-gün (0-day) açıkları satıcıya sorumlu açıklama (Responsible Disclosure) ilkeleri doğrultusunda bildirilmelidir.

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

## 🏗️ Architecture

```
rea-titan/
├── bin/rea-titan                  # Executable CLI launcher
├── rea_titan/
│   ├── cli.py                     # Master CLI entry point (Click + Rich TUI)
│   ├── config.py                  # Auto-discovery for Ghidra, JDK, paths
│   ├── core/
│   │   ├── binary.py              # ELF, PE, Mach-O, Raw format triage
│   │   ├── entropy.py             # Sliding-window Shannon entropy engine
│   │   ├── firmware.py            # Hardware config / router firmware unpackers
│   │   ├── mitigations.py         # Checksec mitigations inspection
│   │   ├── signatures.py          # Crypto S-boxes, hashes & packer signatures
│   │   └── strings.py             # Deep string, secret, and endpoint miner
│   ├── ghidra/
│   │   ├── headless.py            # Ghidra analyzeHeadless process manager
│   │   └── scripts/
│   │       └── TitanExportJson.java # Java script: decompile all functions to JSON
│   ├── bridge/
│   │   ├── mcp_server.py          # Model Context Protocol stdio server
│   │   ├── dynamic_frida.py       # Frida hook script generator
│   │   └── pwntools_gen.py        # Pwntools exploit skeleton generator
│   └── tui/
│       └── console.py             # Rich styling, cyberpunk banners, and tables
```

---

## 📜 License
Licensed under the [MIT License](LICENSE).
