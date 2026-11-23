// Make a function the way analysis does, or write the bodies of the functions in the fixture's no-return pair.
// Args: auto            create a function at the first of the pair, which runs on into the second
//       dump LABEL FILE append "LABEL<TAB>entry<TAB>end exclusive<TAB>name" for each function in the pair's range
// @category RE
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import java.io.FileWriter;
import java.io.PrintWriter;

public class HandProbe extends GhidraScript {
    @Override
    protected void run() throws Exception {
        String[] a = getScriptArgs();
        Address first = toAddr(0xbfc00400L);
        if (a[0].equals("auto")) {
            Function old = getFunctionAt(first);
            if (old != null) currentProgram.getFunctionManager().removeFunction(first);
            Function second = getFunctionAt(toAddr(0xbfc00410L));
            if (second != null) currentProgram.getFunctionManager().removeFunction(second.getEntryPoint());
            disassemble(first);
            createFunction(first, null);
            return;
        }
        try (PrintWriter out = new PrintWriter(new FileWriter(a[2], true))) {
            for (Function f : currentProgram.getFunctionManager().getFunctions(true)) {
                long e = f.getEntryPoint().getOffset();
                if (e >= 0xbfc00400L && e < 0xbfc00420L)
                    out.println(a[1] + "\t0x" + Long.toHexString(e) + "\t0x" + Long.toHexString(f.getBody().getMaxAddress().getOffset() + 1)
                        + "\t" + f.getName());
            }
        }
    }
}
