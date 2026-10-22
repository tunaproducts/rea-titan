# ⚡ REA-TITAN: Windows Handoff & Session State

**Project:** [tunaproducts/rea-titan](https://github.com/tunaproducts/rea-titan)  
**Date:** 2026-10-22  
**Developers:** Murat (Tris) & ENI  

---

## 🎯 Current Status
- The entire **REA-TITAN** repository has been developed, tested, committed, and pushed live to GitHub at:
  👉 `https://github.com/tunaproducts/rea-titan.git`
- Features implemented & operational:
  1. **Interactive AI Copilot** (`.\bin\rea-titan.ps1 copilot <target>`)
  2. **License Key & Anti-Tamper Auditor** (`.\bin\rea-titan.ps1 keys <target>`)
  3. **NSA Ghidra 12 Headless C Decompiler** (`.\bin\rea-titan.ps1 decompile <target> --func <name>`)
  4. **Capstone 5 Disassembly Engine** (`.\bin\rea-titan.ps1 disasm <target>`)
  5. **ROP Gadget Scanner** (`.\bin\rea-titan.ps1 rop <target>`)
  6. **Dangerous C API & Checksec Auditor** (`.\bin\rea-titan.ps1 audit <target>`)
  7. **Shannon Sliding-Window Entropy Scanner** (`.\bin\rea-titan.ps1 entropy <target>`)
  8. **Model Context Protocol (MCP) Server** (`.\bin\rea-titan.ps1 mcp`)
  9. **TITAN-ETHICS-1.0 License**

---

## 🪟 Windows Execution Guide

Once booted into Windows 10/11:

```powershell
# 1. Clone repository
git clone https://github.com/tunaproducts/rea-titan.git
cd rea-titan

# 2. Install dependencies
pip install -r requirements.txt

# 3. Analyze target application (Key-system / Login-protected .exe)
.\bin\rea-titan.ps1 keys "C:\path\to\target.exe"
.\bin\rea-titan.ps1 copilot "C:\path\to\target.exe"
```
