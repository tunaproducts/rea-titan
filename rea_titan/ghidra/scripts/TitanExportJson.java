// Ghidra Headless Script for REA-TITAN: Deep Function Decompilation & JSON Export
// @category REA-TITAN
// @keybinding
// @menupath
// @toolbar

import java.io.File;
import java.io.FileWriter;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;

public class TitanExportJson extends GhidraScript {

    @Override
    public void run() throws Exception {
        println("[REA-TITAN] Starting headless binary decompilation and extraction...");

        String[] args = getScriptArgs();
        String outputFile = (args.length > 0) ? args[0] : "titan_decompiled.json";

        Program program = currentProgram;
        if (program == null) {
            println("[REA-TITAN ERROR] No active program loaded.");
            return;
        }

        DecompInterface decompiler = new DecompInterface();
        decompiler.openProgram(program);

        FunctionManager funcManager = program.getFunctionManager();
        FunctionIterator functions = funcManager.getFunctions(true);

        StringBuilder json = new StringBuilder();
        json.append("{\n");
        json.append("  \"binary_name\": \"").append(escapeJson(program.getName())).append("\",\n");
        json.append("  \"language\": \"").append(escapeJson(program.getLanguage().getLanguageID().getIdAsString())).append("\",\n");
        json.append("  \"compiler\": \"").append(escapeJson(program.getCompilerSpec().getCompilerSpecID().getIdAsString())).append("\",\n");
        json.append("  \"functions_count\": ").append(funcManager.getFunctionCount()).append(",\n");
        json.append("  \"functions\": [\n");

        boolean firstFunc = true;
        int count = 0;

        while (functions.hasNext() && !monitor.isCancelled()) {
            Function func = functions.next();
            if (func.isThunk() || func.isExternal()) {
                continue; // Skip stub thunks for clean export
            }

            count++;
            if (!firstFunc) {
                json.append(",\n");
            }
            firstFunc = false;

            Address entry = func.getEntryPoint();
            String name = func.getName();
            String signature = func.getPrototypeString(true, false);

            // Decompile
            DecompileResults decompRes = decompiler.decompileFunction(func, 30, monitor);
            String decompiledCode = "";
            if (decompRes != null && decompRes.decompileCompleted()) {
                decompiledCode = decompRes.getDecompiledFunction().getC();
            }

            // References (Xrefs to this function)
            List<String> callers = new ArrayList<String>();
            Reference[] refs = func.getSymbol().getReferences(monitor);
            if (refs != null) {
                for (Reference ref : refs) {
                    callers.add(ref.getFromAddress().toString());
                    if (callers.size() >= 10) break;
                }
            }

            json.append("    {\n");
            json.append("      \"name\": \"").append(escapeJson(name)).append("\",\n");
            json.append("      \"entry\": \"0x").append(entry.toString()).append("\",\n");
            json.append("      \"signature\": \"").append(escapeJson(signature)).append("\",\n");
            json.append("      \"callers\": [");
            for (int i = 0; i < callers.size(); i++) {
                json.append("\"").append(callers.get(i)).append("\"");
                if (i < callers.size() - 1) json.append(", ");
            }
            json.append("],\n");
            json.append("      \"decompiled_code\": \"").append(escapeJson(decompiledCode)).append("\"\n");
            json.append("    }");
        }

        json.append("\n  ]\n");
        json.append("}\n");

        decompiler.dispose();

        File out = new File(outputFile);
        PrintWriter writer = new PrintWriter(new FileWriter(out));
        writer.write(json.toString());
        writer.close();

        println("[REA-TITAN] Decompilation export complete! Saved " + count + " functions to " + outputFile);
    }

    private String escapeJson(String raw) {
        if (raw == null) return "";
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < raw.length(); i++) {
            char c = raw.charAt(i);
            switch (c) {
                case '"': sb.append("\\\""); break;
                case '\\': sb.append("\\\\"); break;
                case '\b': sb.append("\\b"); break;
                case '\f': sb.append("\\f"); break;
                case '\n': sb.append("\\n"); break;
                case '\r': sb.append("\\r"); break;
                case '\t': sb.append("\\t"); break;
                default:
                    if (c < ' ') {
                        String t = "000" + Integer.toHexString(c);
                        sb.append("\\u").append(t.substring(t.length() - 4));
                    } else {
                        sb.append(c);
                    }
            }
        }
        return sb.toString();
    }
}
