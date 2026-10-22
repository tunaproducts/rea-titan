"""Frida dynamic instrumentation hook generator."""

from pathlib import Path
from typing import Any, Dict, List, Optional


class FridaHookGenerator:
    """Generates customized Frida scripts for tracing functions, inspecting arguments, and bypassing checks."""

    @staticmethod
    def generate_function_hook(
        binary_name: str,
        func_name_or_offset: str,
        num_args: int = 4,
        read_strings: bool = True,
    ) -> str:
        """Generate a complete JavaScript Frida hook template."""
        is_offset = func_name_or_offset.startswith("0x") or func_name_or_offset.startswith("0X")

        arg_logs = []
        for i in range(num_args):
            if read_strings:
                arg_logs.append(
                    f'            try {{ console.log("  [+] arg{i}: " + args[{i}] + " -> " + Memory.readUtf8String(args[{i}])); }} catch(e) {{ console.log("  [+] arg{i}: " + args[{i}]); }}'
                )
            else:
                arg_logs.append(f'            console.log("  [+] arg{i}: " + args[{i}]);')

        args_str = "\n".join(arg_logs)

        if is_offset:
            target_resolver = f"""
    const baseAddr = Module.getBaseAddress("{binary_name}");
    const targetAddr = baseAddr.add({func_name_or_offset});
    console.log("[*] Hooking offset {func_name_or_offset} at: " + targetAddr);
"""
            interceptor_target = "targetAddr"
        else:
            target_resolver = f"""
    const targetAddr = Module.findExportByName("{binary_name}", "{func_name_or_offset}") || Module.findExportByName(null, "{func_name_or_offset}");
    if (!targetAddr) {{
        console.error("[-] Function {func_name_or_offset} not found!");
        return;
    }}
    console.log("[*] Hooking exported function {func_name_or_offset} at: " + targetAddr);
"""
            interceptor_target = "targetAddr"

        script = f"""// [REA-TITAN] Frida Hook Script for: {binary_name}
// Target: {func_name_or_offset}

Java.perform(function() {{
    // If Android runtime is detected
}});

setImmediate(function() {{
{target_resolver}
    Interceptor.attach({interceptor_target}, {{
        onEnter: function(args) {{
            console.log("\\n[REA-TITAN TRACE] === Entering: {func_name_or_offset} ===");
{args_str}
        }},
        onLeave: function(retval) {{
            console.log("[REA-TITAN TRACE] Return value: " + retval);
        }}
    }});
}});
"""
        return script
