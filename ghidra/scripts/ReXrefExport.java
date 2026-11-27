// Write a program's cross-reference records as JSON lines in a directory, from the call, access and block
// walks (ReCallWalk, ReAccessWalk, ReBlockEval), not the decompiler. tools/ghidra-export.py finish turns them into
// functions.tsv, sites.tsv and strings.tsv.
//   xref-functions.jsonl  every function: entry, end (exclusive), name, name_source, callers, callees, hardware
//                         (access: it has an access record; calls-access: it directly calls a routine that has one)
//   xref-sites.jsonl      for each hardware routine, its accesses and its call sites
//   xref-strings.jsonl    each reference from code to the first byte of a defined string
// A placeholder name (a function Ghidra named itself) is written empty. Addresses are Ghidra's own; the converter
// moves them to the published address space.
// Args: DIRECTORY
// @category RE
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.StringDataInstance;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.SourceType;
import java.io.PrintWriter;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;

public class ReXrefExport extends GhidraScript {
    private final Gson gson = new GsonBuilder().disableHtmlEscaping().create();

    private static String hex(long v) {
        return "0x" + Long.toHexString(v);
    }

    private static String hex(Address a) {
        return hex(a.getOffset());
    }

    @Override
    protected void run() throws Exception {
        long start = System.currentTimeMillis();
        String dir = getScriptArgs()[0];
        List<ReCallWalk.Call> calls = ReCallWalk.walk(currentProgram, monitor);
        List<ReAccessWalk.Access> accesses = ReAccessWalk.walk(currentProgram, monitor);
        long walked = System.currentTimeMillis();

        Map<Long, Set<Long>> callers = new HashMap<>(), callees = new HashMap<>();
        Map<Long, String> hardware = new HashMap<>();
        for (ReAccessWalk.Access x : accesses) hardware.put(x.function.getOffset(), "access");
        for (ReCallWalk.Call c : calls) {
            if (c.target == null) continue;
            long from = c.function.getOffset(), to = c.target.getOffset();
            callees.computeIfAbsent(from, k -> new TreeSet<>()).add(to);
            callers.computeIfAbsent(to, k -> new TreeSet<>()).add(from);
        }
        for (ReCallWalk.Call c : calls)
            if (c.target != null && "access".equals(hardware.get(c.target.getOffset()))
                && !hardware.containsKey(c.function.getOffset())) hardware.put(c.function.getOffset(), "calls-access");

        try (PrintWriter out = new PrintWriter(Paths.get(dir, "xref-functions.jsonl").toFile(), "UTF-8")) {
            for (Function f : currentProgram.getFunctionManager().getFunctions(true)) {
                if (f.isExternal()) continue;
                long e = f.getEntryPoint().getOffset();
                SourceType src = f.getSymbol().getSource();
                Map<String, Object> row = new LinkedHashMap<>();
                row.put("entry", hex(e));
                row.put("end", hex(f.getBody().getMaxAddress().getOffset() + 1));
                row.put("name", src == SourceType.DEFAULT ? "" : f.getName());
                row.put("name_source", src == SourceType.DEFAULT ? "" : src.name().toLowerCase());
                row.put("callers", hexes(callers.get(e)));
                row.put("callees", hexes(callees.get(e)));
                row.put("hardware", hardware.getOrDefault(e, ""));
                out.println(gson.toJson(row));
            }
        }

        int sites = 0;
        try (PrintWriter out = new PrintWriter(Paths.get(dir, "xref-sites.jsonl").toFile(), "UTF-8")) {
            for (ReAccessWalk.Access x : accesses) {
                Map<String, Object> row = new LinkedHashMap<>();
                row.put("function", hex(x.function));
                row.put("site", hex(x.site));
                row.put("kind", x.op);
                row.put("address", hex(x.address));
                row.put("physical", hex(x.physical));
                row.put("width", x.width);
                row.put("value", x.value);
                row.put("uses", x.uses);
                row.put("grade", "established");
                out.println(gson.toJson(row));
                sites++;
            }
            for (ReCallWalk.Call c : calls) {
                if (!hardware.containsKey(c.function.getOffset())) continue;
                String how = c.kind + (c.source == null ? "" : "@" + hex(c.source)) + (c.tail ? " tail" : "");
                Map<String, Object> row = new LinkedHashMap<>();
                row.put("function", hex(c.function));
                row.put("site", hex(c.site));
                row.put("kind", "call");
                row.put("target", (c.target == null ? "?" : hex(c.target)) + " " + how);
                row.put("grade", "established");
                out.println(gson.toJson(row));
                sites++;
            }
        }

        Map<Long, String> strings = new HashMap<>();
        // Only strings in the loaded image: an ELF file's non-loaded sections (symbol names, debug text) are overlay
        // blocks whose offsets repeat the loaded ones.
        for (Data d : currentProgram.getListing().getDefinedData(true)) {
            MemoryBlock block = currentProgram.getMemory().getBlock(d.getAddress());
            if (block == null || !block.isInitialized() || !block.isLoaded() || block.isOverlay() || !StringDataInstance.isString(d)) continue;
            String text = StringDataInstance.getStringDataInstance(d).getStringValue();
            if (text != null && !text.isEmpty()) strings.put(d.getAddress().getOffset(), text);
        }
        long walkRefs = 0, analysisRefs = 0;
        Set<String> seen = new LinkedHashSet<>();
        try (PrintWriter out = new PrintWriter(Paths.get(dir, "xref-strings.jsonl").toFile(), "UTF-8")) {
            long max = currentProgram.getAddressFactory().getDefaultAddressSpace().getMaxAddress().getOffset();
            if (!strings.isEmpty()) {
                for (Function f : currentProgram.getFunctionManager().getFunctions(true)) {
                    if (f.isExternal() || f.isThunk()) continue;
                    monitor.checkCancelled();
                    new ReBlockEval(currentProgram).walk(f, new ReBlockEval.Listener() {
                        @Override
                        public void constant(Address site, long value) {
                            long v = value & max;
                            if (strings.containsKey(v)) emitString(out, seen, v, strings.get(v), f.getEntryPoint(), site);
                        }
                    });
                }
            }
            walkRefs = seen.size();
            // Ghidra's own references find what the block walk cannot, such as a global-pointer-relative address.
            for (Map.Entry<Long, String> e : strings.entrySet()) {
                monitor.checkCancelled();
                Address at = currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(e.getKey());
                for (Reference r : currentProgram.getReferenceManager().getReferencesTo(at)) {
                    Function f = currentProgram.getFunctionManager().getFunctionContaining(r.getFromAddress());
                    if (f != null && currentProgram.getListing().getInstructionContaining(r.getFromAddress()) != null)
                        emitString(out, seen, e.getKey(), e.getValue(), f.getEntryPoint(), r.getFromAddress());
                }
            }
            analysisRefs = seen.size() - walkRefs;
        }
        println("re-xref-export: " + currentProgram.getFunctionManager().getFunctionCount() + " functions, " + hardware.size()
            + " hardware, " + accesses.size() + " accesses, " + calls.size() + " calls, " + sites + " site rows, " + strings.size()
            + " strings, " + walkRefs + " references from the block walk, " + analysisRefs + " more from Ghidra's references; start "
            + start + ", walks " + (walked - start) / 1000 + " s, strings " + (System.currentTimeMillis() - walked) / 1000 + " s");
    }

    private void emitString(PrintWriter out, Set<String> seen, long string, String text, Address function, Address site) {
        if (!seen.add(function.getOffset() + ":" + site.getOffset() + ":" + string)) return;
        Map<String, Object> row = new LinkedHashMap<>();
        row.put("string", hex(string));
        row.put("text", text);
        row.put("function", hex(function));
        row.put("site", hex(site));
        out.println(gson.toJson(row));
    }

    private static List<String> hexes(Set<Long> set) {
        List<String> out = new ArrayList<>();
        if (set != null) for (long v : set) out.add(hex(v));
        return out;
    }
}
