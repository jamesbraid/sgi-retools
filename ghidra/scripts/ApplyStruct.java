// Parse a C header with structure definitions and give named functions a
// pointer-to-structure first parameter, so the decompiler prints field names.
// Run it before the decompile script (both as post-scripts, in that order).
//
// Arguments: HEADER STRUCT FUNCTION[:COUNT][,FUNCTION[:COUNT]...]
//   HEADER    C source holding "struct STRUCT { ... };" (no #include lines)
//   STRUCT    structure tag to apply
//   FUNCTION  functions whose first parameter is "struct STRUCT *"; COUNT is the
//             parameter count (default 1), the others are 64-bit integers
// Use the same header the m2c context file uses, with explicit-width types,
// so the two outputs can be compared. Prints what it applied.
// @category RE
import ghidra.app.script.GhidraScript;
import ghidra.app.util.cparser.C.CParser;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.SourceType;
import ghidra.app.cmd.function.ApplyFunctionSignatureCmd;
import java.nio.file.*;
import java.util.*;

public class ApplyStruct extends GhidraScript {
    @Override
    public void run() throws Exception {
        String[] a = getScriptArgs();
        String text = new String(Files.readAllBytes(Paths.get(a[0])));
        DataTypeManager dtm = currentProgram.getDataTypeManager();
        CParser parser = new CParser(dtm);
        parser.parse(text);
        DataType st = parser.getComposites().get(a[1]);
        if (st == null) st = parser.getComposites().get("struct " + a[1]);
        if (st == null) {
            Iterator<Structure> si = dtm.getAllStructures();
            while (si.hasNext()) { Structure c = si.next(); if (c.getName().equals(a[1])) st = c; }
        }
        if (st == null) { printerr("ApplyStruct: struct " + a[1] + " not found after parsing"); return; }
        st = dtm.resolve(st, DataTypeConflictHandler.REPLACE_HANDLER);
        PointerDataType p = new PointerDataType(st, dtm);
        for (String spec : a[2].split(",")) {
            String n = spec.contains(":") ? spec.substring(0, spec.indexOf(':')) : spec;
            int count = spec.contains(":") ? Integer.parseInt(spec.substring(spec.indexOf(':') + 1)) : 1;
            for (Function f : getGlobalFunctions(n)) {
                List<Variable> params = new ArrayList<>();
                params.add(new ParameterImpl("p", p, currentProgram));
                for (int k = 1; k < count; k++)
                    params.add(new ParameterImpl("arg" + k, new LongLongDataType(), currentProgram));
                int tx = currentProgram.startTransaction("apply");
                try {
                    f.replaceParameters(params, Function.FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS,
                        true, SourceType.USER_DEFINED);
                    println("ApplyStruct: " + n + " now takes " + count + " parameter(s), the first a " + p.getName());
                } finally { currentProgram.endTransaction(tx, true); }
            }
        }
    }
}
