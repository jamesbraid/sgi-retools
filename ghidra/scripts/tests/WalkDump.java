// Write what ReCallWalk and ReAccessWalk find, one record a line, in the columns mips_synthetic.py expects.
// Args: CALLS_FILE ACCESSES_FILE
// @category RE
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import java.io.PrintWriter;

public class WalkDump extends GhidraScript {
    private static String hex(Address a) {
        return a == null ? "-" : "0x" + Long.toHexString(a.getOffset());
    }

    @Override
    protected void run() throws Exception {
        String[] a = getScriptArgs();
        try (PrintWriter out = new PrintWriter(a[0])) {
            for (ReCallWalk.Call c : ReCallWalk.walk(currentProgram, monitor))
                out.println(hex(c.site) + "\t" + hex(c.function) + "\t" + hex(c.target) + "\t" + c.kind + "\t"
                    + hex(c.source) + "\t" + (c.tail ? "1" : "0"));
        }
        try (PrintWriter out = new PrintWriter(a[1])) {
            for (ReAccessWalk.Access x : ReAccessWalk.walk(currentProgram, monitor))
                out.println(hex(x.site) + "\t" + hex(x.function) + "\t0x" + Long.toHexString(x.address) + "\t0x" + Long.toHexString(x.physical) + "\t" + x.width
                    + "\t" + x.op + "\t" + x.addressing + "\t" + hex(x.base) + "\t" + hex(x.loadSite));
        }
    }
}
