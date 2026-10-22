"""REA-TITAN Model Context Protocol (MCP) Server for AI Agent Integration."""

import json
import sys
from pathlib import Path
from typing import Any, Dict, List

from rea_titan.core.binary import BinaryTriage
from rea_titan.core.entropy import EntropyScanner
from rea_titan.core.mitigations import MitigationsChecker
from rea_titan.core.signatures import SignatureDetector
from rea_titan.core.strings import StringMiner
from rea_titan.ghidra.headless import GhidraHeadlessEngine
from rea_titan.bridge.dynamic_frida import FridaHookGenerator


TOOLS_METADATA = [
    {
        "name": "titan_triage_binary",
        "description": "Performs fast static triage on a binary file (format, architecture, bitness, entry point, symbols).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "filepath": {"type": "string", "description": "Absolute path to the target binary."}
            },
            "required": ["filepath"],
        },
    },
    {
        "name": "titan_entropy_scan",
        "description": "Calculates Shannon entropy to detect packed, encrypted, or compressed sections in binaries/firmware.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "filepath": {"type": "string", "description": "Absolute path to the binary or firmware file."}
            },
            "required": ["filepath"],
        },
    },
    {
        "name": "titan_extract_strings",
        "description": "Extracts and filters interesting strings (IPs, URLs, tokens, shell commands, paths).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "filepath": {"type": "string", "description": "Absolute path to the binary."},
                "min_length": {"type": "integer", "description": "Minimum string length (default 5).", "default": 5}
            },
            "required": ["filepath"],
        },
    },
    {
        "name": "titan_check_mitigations",
        "description": "Checks security mitigations (NX/DEP, PIE, Stack Canary, RELRO, Fortify).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "filepath": {"type": "string", "description": "Absolute path to the binary."}
            },
            "required": ["filepath"],
        },
    },
    {
        "name": "titan_scan_crypto_signatures",
        "description": "Scans for AES S-Boxes, SHA/MD5 constants, ChaCha20 patterns, and known compiler/packer signatures.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "filepath": {"type": "string", "description": "Absolute path to the binary."}
            },
            "required": ["filepath"],
        },
    },
    {
        "name": "titan_decompile_binary",
        "description": "Invokes Ghidra headless decompiler to decompile all functions into C pseudocode and xrefs.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "filepath": {"type": "string", "description": "Absolute path to the binary."}
            },
            "required": ["filepath"],
        },
    },
    {
        "name": "titan_generate_frida_hook",
        "description": "Generates a ready-to-run Frida hook script for intercepting target function calls and arguments.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "binary_name": {"type": "string", "description": "Target process or binary name."},
                "target_func": {"type": "string", "description": "Function name or offset (e.g., '0x1234' or 'auth_check')."},
                "num_args": {"type": "integer", "description": "Number of arguments to inspect.", "default": 4}
            },
            "required": ["binary_name", "target_func"],
        },
    },
    {
        "name": "titan_audit_vulnerabilities",
        "description": "Audits binary for dangerous C standard library APIs (gets, strcpy, sprintf, system) and insecure functions.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "filepath": {"type": "string", "description": "Absolute path to the binary."}
            },
            "required": ["filepath"],
        },
    },
    {
        "name": "titan_scan_rop_gadgets",
        "description": "Scans binary for common ROP gadgets to evaluate exploitation mitigation resilience.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "filepath": {"type": "string", "description": "Absolute path to the binary."}
            },
            "required": ["filepath"],
        },
    },
    {
        "name": "titan_disassemble_offset",
        "description": "Performs fast Capstone disassembly on a given offset in the binary.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "filepath": {"type": "string", "description": "Absolute path to the binary."},
                "offset": {"type": "integer", "description": "Byte offset to disassemble.", "default": 0},
                "count": {"type": "integer", "description": "Number of instructions to decode.", "default": 20}
            },
            "required": ["filepath"],
        },
    },
]


def handle_tool_call(name: str, args: Dict[str, Any]) -> Any:
    filepath = args.get("filepath", "")

    if name == "titan_triage_binary":
        triage = BinaryTriage(filepath)
        return triage.full_triage()

    elif name == "titan_entropy_scan":
        scanner = EntropyScanner(filepath)
        return scanner.scan()

    elif name == "titan_extract_strings":
        min_len = args.get("min_length", 5)
        miner = StringMiner(filepath, min_length=min_len)
        return miner.mine_secrets_and_endpoints()

    elif name == "titan_check_mitigations":
        checker = MitigationsChecker(filepath)
        return checker.analyze()

    elif name == "titan_scan_crypto_signatures":
        sig = SignatureDetector(filepath)
        return sig.scan()

    elif name == "titan_decompile_binary":
        engine = GhidraHeadlessEngine()
        return engine.decompile_binary(filepath)

    elif name == "titan_audit_vulnerabilities":
        from rea_titan.core.auditor import SecurityAuditor
        return SecurityAuditor(filepath).audit_apis()

    elif name == "titan_scan_rop_gadgets":
        from rea_titan.core.rop import ROPGadgetScanner
        return ROPGadgetScanner(filepath).scan_gadgets()

    elif name == "titan_disassemble_offset":
        from rea_titan.core.disasm import FastDisassembler
        off = args.get("offset", 0)
        cnt = args.get("count", 20)
        return FastDisassembler().disassemble_file_offset(filepath, offset=off, length=cnt * 8)

    raise ValueError(f"Unknown tool: {name}")


def run_mcp_server():
    """Run JSON-RPC 2.0 stdio loop for MCP clients."""
    sys.stderr.write("[REA-TITAN MCP] Server initialized on stdio. Listening for agent requests...\n")
    sys.stderr.flush()

    for line in sys.stdin:
        if not line.strip():
            continue
        try:
            req = json.loads(line)
            req_id = req.get("id")
            method = req.get("method")

            if method == "initialize":
                res = {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": {
                        "protocolVersion": "2024-11-05",
                        "capabilities": {"tools": {}},
                        "serverInfo": {
                            "name": "rea-titan-mcp",
                            "version": "1.0.0",
                        },
                    },
                }
            elif method == "notifications/initialized":
                continue
            elif method == "tools/list":
                res = {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": {"tools": TOOLS_METADATA},
                }
            elif method == "tools/call":
                params = req.get("params", {})
                tool_name = params.get("name")
                tool_args = params.get("arguments", {})
                try:
                    tool_res = handle_tool_call(tool_name, tool_args)
                    res = {
                        "jsonrpc": "2.0",
                        "id": req_id,
                        "result": {
                            "content": [
                                {
                                    "type": "text",
                                    "text": json.dumps(tool_res, indent=2) if isinstance(tool_res, (dict, list)) else str(tool_res),
                                }
                            ]
                        },
                    }
                except Exception as e:
                    res = {
                        "jsonrpc": "2.0",
                        "id": req_id,
                        "result": {
                            "content": [{"type": "text", "text": f"Tool Execution Error: {str(e)}"}],
                            "isError": True,
                        },
                    }
            else:
                res = {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "error": {"code": -32601, "message": f"Method not found: {method}"},
                }

            sys.stdout.write(json.dumps(res) + "\n")
            sys.stdout.flush()

        except Exception as err:
            sys.stderr.write(f"[REA-TITAN MCP ERROR] {str(err)}\n")
            sys.stderr.flush()


if __name__ == "__main__":
    run_mcp_server()
