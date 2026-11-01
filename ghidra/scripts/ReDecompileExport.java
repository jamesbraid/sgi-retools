/* Export Ghidra's decompiled C per function as JSON lines, optionally after
 * applying reader-maintained structure types.
 *
 * Runs as a headless -postScript after analysis. Reads /work/out/<dir>/export.json,
 * which tools/ghidra-export.py writes:
 *
 *   { "all": bool, "names": [..], "addresses": ["0x.."], "glob": [..],
 *     "timeout": seconds, "types": { ...spec... } | null }
 *
 * Addresses are Ghidra's own (the converter moves them to the published
 * address space on the way out). The types spec is documented in
 * ghidra/README.md.
 *
 * Output, in the same directory:
 *   functions.jsonl   one object per function
 *   types.json        what was applied and what was not
 *
 * Decompiler output is navigation. Nothing here makes it evidence.
 *
 * @category RE
 */

import java.io.IOException;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import ghidra.app.cmd.function.ApplyFunctionSignatureCmd;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.app.util.cparser.C.CParser;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.program.model.listing.Variable;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;

public class ReDecompileExport extends GhidraScript {
    private static final CategoryPath CATEGORY = new CategoryPath("/re");
    // The decompiler reports what it could not trust as block comments in the
    // C it prints. These are the shapes it uses.
    private static final Pattern WARNING = Pattern.compile(
        "/\\*\\s*((?:WARNING|Warning|Unable|Could not|Bad instruction|Control flow|Removing unreachable|Restart)[^*]*(?:\\*(?!/)[^*]*)*)\\*/");

    private final Gson gson = new GsonBuilder().disableHtmlEscaping().create();
    private final List<String> notes = new ArrayList<>();
    private final List<String> unmatched = new ArrayList<>();
    private final Set<String> appliedFunctions = new LinkedHashSet<>();
    private final List<String> structsMade = new ArrayList<>();
    private int globalsApplied = 0;

    private PrintWriter writer(Path path) throws IOException {
        return new PrintWriter(Files.newBufferedWriter(path, StandardCharsets.UTF_8,
            StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING,
            StandardOpenOption.WRITE));
    }

    private String hex(Address address) {
        return "0x" + Long.toUnsignedString(address.getOffset(), 16);
    }

    // ---- types -----------------------------------------------------------

    private DataType builtin(String name) {
        switch (name) {
            case "void": return VoidDataType.dataType;
            case "char": case "s8": case "int8_t": case "signed char": return new CharDataType();
            case "u8": case "uint8_t": case "unsigned char": return new UnsignedCharDataType();
            case "s16": case "int16_t": case "short": return new ShortDataType();
            case "u16": case "uint16_t": case "unsigned short": return new UnsignedShortDataType();
            case "s32": case "int32_t": case "int": return new IntegerDataType();
            case "u32": case "uint32_t": case "unsigned int": case "unsigned": return new UnsignedIntegerDataType();
            case "s64": case "int64_t": case "long long": return new LongLongDataType();
            case "u64": case "uint64_t": case "unsigned long long": return new UnsignedLongLongDataType();
            case "f32": case "float": return new FloatDataType();
            case "f64": case "double": return new DoubleDataType();
            default: return null;
        }
    }

    private DataType lookup(String name, DataTypeManager dtm) {
        DataType made = dtm.getDataType(CATEGORY, name);
        if (made != null) {
            return made;
        }
        List<DataType> found = new ArrayList<>();
        dtm.findDataTypes(name, found);
        return found.isEmpty() ? null : found.get(0);
    }

    /* "u32", "struct gc *", "gc **", "u8[16]", "void *". Returns null and
     * records a note when the name is unknown, so a typo fails loudly. */
    private DataType parseType(String text, DataTypeManager dtm) {
        String s = text.trim();
        Matcher array = Pattern.compile("^(.*)\\[(\\d+)\\]$").matcher(s);
        if (array.matches()) {
            DataType element = parseType(array.group(1), dtm);
            if (element == null) {
                return null;
            }
            int count = Integer.parseInt(array.group(2));
            return new ArrayDataType(element, count, element.getLength());
        }
        if (s.endsWith("*")) {
            String inner = s.substring(0, s.length() - 1).trim();
            DataType target = inner.isEmpty() || inner.equals("void") ? VoidDataType.dataType
                : parseType(inner, dtm);
            return target == null ? null : new PointerDataType(target, dtm);
        }
        s = s.replaceFirst("^(struct|union|enum)\\s+", "");
        DataType type = builtin(s);
        if (type == null) {
            type = lookup(s, dtm);
        }
        if (type == null) {
            notes.add("unknown type: " + text);
        }
        return type;
    }

    private void applyHeaders(JsonObject spec, DataTypeManager dtm) throws Exception {
        if (!spec.has("headers")) {
            return;
        }
        for (JsonElement header : spec.getAsJsonArray("headers")) {
            String text = Files.readString(Paths.get(header.getAsString()));
            CParser parser = new CParser(dtm);
            parser.parse(text);
            for (DataType type : parser.getComposites().values()) {
                dtm.resolve(type, DataTypeConflictHandler.REPLACE_HANDLER);
            }
            for (DataType type : parser.getTypes().values()) {
                dtm.resolve(type, DataTypeConflictHandler.REPLACE_HANDLER);
            }
            structsMade.add("header " + header.getAsString());
        }
    }

    private void applyStructs(JsonObject spec, DataTypeManager dtm) {
        if (!spec.has("structs")) {
            return;
        }
        JsonArray structs = spec.getAsJsonArray("structs");
        // Declare every struct first so a field may point at one defined later.
        for (JsonElement element : structs) {
            JsonObject definition = element.getAsJsonObject();
            StructureDataType declared = new StructureDataType(CATEGORY,
                definition.get("name").getAsString(), definition.get("size").getAsInt(), dtm);
            dtm.resolve(declared, DataTypeConflictHandler.REPLACE_HANDLER);
        }
        for (JsonElement element : structs) {
            JsonObject definition = element.getAsJsonObject();
            String name = definition.get("name").getAsString();
            Structure target = (Structure) dtm.getDataType(CATEGORY, name);
            for (JsonElement fieldElement : definition.getAsJsonArray("fields")) {
                JsonObject field = fieldElement.getAsJsonObject();
                DataType type = parseType(field.get("type").getAsString(), dtm);
                if (type == null) {
                    continue;
                }
                int offset = field.get("offset").getAsInt();
                int length = field.has("size") ? field.get("size").getAsInt() : type.getLength();
                if (offset + length > target.getLength()) {
                    notes.add(name + "." + field.get("name").getAsString() + " overruns the struct");
                    continue;
                }
                String comment = field.has("comment") ? field.get("comment").getAsString() : null;
                target.replaceAtOffset(offset, type, length, field.get("name").getAsString(), comment);
            }
            structsMade.add(name);
        }
    }

    private List<Function> matching(String pattern) {
        List<Function> out = new ArrayList<>();
        if (pattern.startsWith("@0x")) {
            Function function = getFunctionContaining(toAddr(Long.parseUnsignedLong(pattern.substring(3), 16)));
            if (function != null) {
                out.add(function);
            }
        }
        else if (pattern.contains("*")) {
            StringBuilder regex = new StringBuilder();
            for (String piece : pattern.split("\\*", -1)) {
                if (regex.length() > 0) {
                    regex.append(".*");
                }
                regex.append(Pattern.quote(piece));
            }
            Pattern glob = Pattern.compile(regex.toString());
            FunctionIterator all = currentProgram.getFunctionManager().getFunctions(true);
            while (all.hasNext()) {
                Function function = all.next();
                if (glob.matcher(function.getName()).matches()) {
                    out.add(function);
                }
            }
        }
        else {
            out.addAll(getGlobalFunctions(pattern));
        }
        return out;
    }

    private void applyFunctions(JsonObject spec, DataTypeManager dtm) throws Exception {
        if (!spec.has("functions")) {
            return;
        }
        for (JsonElement element : spec.getAsJsonArray("functions")) {
            JsonObject entry = element.getAsJsonObject();
            String match = entry.get("match").getAsString();
            List<Function> functions = matching(match);
            if (functions.isEmpty()) {
                notes.add("no function matches " + match);
                continue;
            }
            for (Function function : functions) {
                List<Variable> params = new ArrayList<>();
                int index = 0;
                boolean ok = true;
                for (JsonElement paramElement : entry.getAsJsonArray("params")) {
                    JsonObject param = paramElement.getAsJsonObject();
                    DataType type = parseType(param.get("type").getAsString(), dtm);
                    if (type == null) {
                        ok = false;
                        break;
                    }
                    String name = param.has("name") ? param.get("name").getAsString() : "arg" + index;
                    params.add(new ParameterImpl(name, type, currentProgram));
                    index++;
                }
                if (!ok) {
                    continue;
                }
                int transaction = currentProgram.startTransaction("re apply types");
                try {
                    function.replaceParameters(params,
                        Function.FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS,
                        true, SourceType.USER_DEFINED);
                    if (entry.has("returns")) {
                        DataType type = parseType(entry.get("returns").getAsString(), dtm);
                        if (type != null) {
                            function.setReturnType(type, SourceType.USER_DEFINED);
                        }
                    }
                    // Replacing the parameters leaves the convention unknown, which
                    // the decompiler then flags on every routine it prints.
                    function.setCallingConvention(entry.has("calling_convention")
                        ? entry.get("calling_convention").getAsString()
                        : Function.DEFAULT_CALLING_CONVENTION_STRING);
                    appliedFunctions.add(function.getName());
                }
                finally {
                    currentProgram.endTransaction(transaction, true);
                }
            }
        }
    }

    private void applyGlobals(JsonObject spec, DataTypeManager dtm) throws Exception {
        if (!spec.has("globals")) {
            return;
        }
        for (JsonElement element : spec.getAsJsonArray("globals")) {
            JsonObject entry = element.getAsJsonObject();
            DataType type = parseType(entry.get("type").getAsString(), dtm);
            if (type == null) {
                continue;
            }
            Address address = toAddr(Long.parseUnsignedLong(entry.get("address").getAsString().substring(2), 16));
            int transaction = currentProgram.startTransaction("re apply global");
            try {
                clearListing(address, address.add(type.getLength() - 1));
                createData(address, type);
                if (entry.has("name")) {
                    createLabel(address, entry.get("name").getAsString(), true);
                }
                globalsApplied++;
            }
            finally {
                currentProgram.endTransaction(transaction, true);
            }
        }
    }

    private void applyTypes(JsonObject spec) throws Exception {
        if (spec.has("pointer_bytes")
                && spec.get("pointer_bytes").getAsInt() != currentProgram.getDefaultPointerSize()) {
            notes.add("spec is for " + spec.get("pointer_bytes").getAsInt()
                + "-byte pointers; program has " + currentProgram.getDefaultPointerSize()
                + "; nothing applied");
            return;
        }
        DataTypeManager dtm = currentProgram.getDataTypeManager();
        int transaction = currentProgram.startTransaction("re structs");
        try {
            applyHeaders(spec, dtm);
            applyStructs(spec, dtm);
        }
        finally {
            currentProgram.endTransaction(transaction, true);
        }
        applyFunctions(spec, dtm);
        applyGlobals(spec, dtm);
    }

    // ---- export ----------------------------------------------------------

    private Map<String, Object> record(DecompInterface engine, Function function, int timeout) {
        Map<String, Object> row = new LinkedHashMap<>();
        Symbol symbol = function.getSymbol();
        row.put("name", function.getName());
        row.put("name_source", symbol.getSource().toString());
        row.put("address", hex(function.getEntryPoint()));
        row.put("end", hex(function.getBody().getMaxAddress()));
        row.put("bytes", function.getBody().getNumAddresses());
        row.put("signature", function.getPrototypeString(false, false));
        row.put("calling_convention", function.getCallingConventionName());
        long start = System.nanoTime();
        DecompileResults result = engine.decompileFunction(function, timeout, monitor);
        row.put("decompile_ms", (System.nanoTime() - start) / 1_000_000);
        boolean complete = result != null && result.decompileCompleted()
            && result.getDecompiledFunction() != null;
        row.put("complete", complete);
        List<String> warnings = new ArrayList<>();
        if (complete) {
            String c = result.getDecompiledFunction().getC();
            row.put("c", c);
            Matcher matcher = WARNING.matcher(c);
            while (matcher.find()) {
                warnings.add(matcher.group(1).trim().replaceAll("\\s+", " "));
            }
        }
        else {
            row.put("error", result == null ? "decompiler did not open program"
                : result.isTimedOut() ? "timeout" : String.valueOf(result.getErrorMessage()));
        }
        row.put("warnings", warnings);
        return row;
    }

    /* Two ways in. tools/ghidra-export.py passes one directory and writes
     * export.json there. A person running Ghidra by hand passes options
     * instead:
     *   --out DIR [--all] [--symbol NAME|GLOB|@0xADDR]... [--types SPEC.json]
     *   [--timeout SECONDS]
     * Both end in the same request. */
    private JsonObject readRequest(String[] args, Path[] directory) throws Exception {
        if (args.length == 1) {
            directory[0] = Paths.get(args[0]).normalize();
            if (Files.isSymbolicLink(directory[0])) {
                throw new IllegalArgumentException("output must not be a symbolic link");
            }
            return JsonParser.parseString(Files.readString(directory[0].resolve("export.json"),
                StandardCharsets.UTF_8)).getAsJsonObject();
        }
        JsonObject request = new JsonObject();
        JsonArray names = new JsonArray();
        request.addProperty("all", false);
        request.add("glob", new JsonArray());
        request.add("addresses", new JsonArray());
        for (int i = 0; i < args.length; i++) {
            switch (args[i]) {
                case "--out": directory[0] = Paths.get(args[++i]).normalize(); break;
                case "--all": request.addProperty("all", true); break;
                case "--symbol": names.add(args[++i]); break;
                case "--timeout": request.addProperty("timeout", Integer.parseInt(args[++i])); break;
                case "--types":
                    request.add("types", JsonParser.parseString(
                        Files.readString(Paths.get(args[++i]), StandardCharsets.UTF_8)));
                    break;
                default: throw new IllegalArgumentException("unknown option " + args[i]);
            }
        }
        if (directory[0] == null) {
            throw new IllegalArgumentException("--out DIR is required");
        }
        Files.createDirectories(directory[0]);
        request.add("names", names);
        return request;
    }

    @Override
    public void run() throws Exception {
        Path[] where = new Path[1];
        JsonObject request = readRequest(getScriptArgs(), where);
        Path directory = where[0];
        int timeout = request.has("timeout") ? request.get("timeout").getAsInt() : 60;
        if (request.has("types") && !request.get("types").isJsonNull()) {
            applyTypes(request.getAsJsonObject("types"));
        }
        Set<Function> chosen = new LinkedHashSet<>();
        if (request.get("all").getAsBoolean()) {
            FunctionIterator all = currentProgram.getFunctionManager().getFunctions(true);
            while (all.hasNext()) {
                chosen.add(all.next());
            }
        }
        for (JsonElement name : request.getAsJsonArray("names")) {
            List<Function> found = matching(name.getAsString());
            if (found.isEmpty()) {
                unmatched.add(name.getAsString());
            }
            chosen.addAll(found);
        }
        for (JsonElement glob : request.getAsJsonArray("glob")) {
            List<Function> found = matching(glob.getAsString());
            if (found.isEmpty()) {
                unmatched.add(glob.getAsString());
            }
            chosen.addAll(found);
        }
        for (JsonElement address : request.getAsJsonArray("addresses")) {
            List<Function> found = matching("@" + address.getAsString());
            if (found.isEmpty()) {
                unmatched.add("@" + address.getAsString());
            }
            chosen.addAll(found);
        }
        DecompInterface engine = new DecompInterface();
        boolean opened = engine.openProgram(currentProgram);
        int done = 0;
        try (PrintWriter out = writer(directory.resolve("functions.jsonl"))) {
            for (Function function : chosen) {
                monitor.checkCancelled();
                Map<String, Object> row;
                // The decompiler's own log lines (pcode errors, unresolved
                // flow) name no function in the C. These markers let the
                // converter attach them to the routine being decompiled.
                println("re-export-begin " + hex(function.getEntryPoint()));
                if (opened) {
                    try {
                        row = record(engine, function, timeout);
                    }
                    catch (Exception error) {
                        row = new LinkedHashMap<>();
                        row.put("name", function.getName());
                        row.put("address", hex(function.getEntryPoint()));
                        row.put("complete", false);
                        row.put("error", error.toString());
                        row.put("warnings", new ArrayList<String>());
                    }
                }
                else {
                    row = new LinkedHashMap<>();
                    row.put("name", function.getName());
                    row.put("address", hex(function.getEntryPoint()));
                    row.put("complete", false);
                    row.put("error", "decompiler did not open program");
                    row.put("warnings", new ArrayList<String>());
                }
                println("re-export-end " + hex(function.getEntryPoint()));
                out.println(gson.toJson(row));
                if (Boolean.TRUE.equals(row.get("complete"))) {
                    done++;
                }
            }
            if (out.checkError()) {
                throw new IOException("function export could not be written completely");
            }
        }
        finally {
            engine.dispose();
        }
        Map<String, Object> summary = new LinkedHashMap<>();
        summary.put("structs", structsMade);
        summary.put("functions_typed", appliedFunctions);
        summary.put("globals_typed", globalsApplied);
        summary.put("notes", notes);
        summary.put("unmatched", unmatched);
        try (PrintWriter out = writer(directory.resolve("types.json"))) {
            out.println(gson.toJson(summary));
        }
        println("re-decompile-export: " + done + "/" + chosen.size() + " decompiled");
    }
}
