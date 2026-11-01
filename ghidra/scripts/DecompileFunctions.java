// Decompile named functions of the program Ghidra just analysed.
// Arguments: OUTFILE name[,name...]
// A name may also be a virtual address written @0x...; for a shared object
// Ghidra keeps the link address, so it is the one objdump shows. Needed for
// static functions in a stripped library, which carry no symbol.
// @category RE
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.address.*;
import java.io.*;
import java.util.*;

public class DecompileFunctions extends GhidraScript {
    @Override
    public void run() throws Exception {
        String[] a = getScriptArgs();
        PrintWriter out = new PrintWriter(new FileWriter(a[0]));
        DecompInterface di = new DecompInterface();
        di.openProgram(currentProgram);
        for (String n : a[1].split(",")) {
            List<Function> fs = new ArrayList<>();
            if (n.startsWith("@0x")) {
                long va = Long.decode(n.substring(1));
                Function f = getFunctionContaining(toAddr(va));
                if (f != null) fs.add(f);
            } else {
                fs.addAll(getGlobalFunctions(n));
            }
            if (fs.isEmpty()) { out.println("//// " + n + " NOT FOUND"); continue; }
            for (Function f : fs) {
                long t0 = System.nanoTime();
                DecompileResults r = di.decompileFunction(f, 120, monitor);
                long ms = (System.nanoTime() - t0) / 1000000;
                out.println("//// " + n + " @" + f.getEntryPoint() + " bytes=" + f.getBody().getNumAddresses()
                    + " decompile_ms=" + ms + " ok=" + r.decompileCompleted());
                if (r.decompileCompleted()) out.println(r.getDecompiledFunction().getC());
                else out.println("// " + r.getErrorMessage());
            }
        }
        out.close();
    }
}
