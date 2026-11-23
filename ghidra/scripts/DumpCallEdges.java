// Dump the call edges of the program as tab-separated rows:
//   program, caller, callee, kind
// kind is "direct" for a call to a named function or external symbol and
// "indirect" for a register call Ghidra could not resolve (callee "?").
// Appends to the file named by the first argument, so a run over many
// programs gives one table; join them by name to walk a call graph that spans
// objects (a relocatable object names its other-object callees as externals).
// A second argument, "sites", writes one row per call site instead, from the instructions' p-code (ReCallWalk),
// with three columns after those four: site (the call instruction), target (the callee's entry, empty when
// unresolved) and resolved_by (direct, constant, table or unresolved). A call that is not resolved to one
// address has callee "?" and kind "indirect". Jumps to another function's entry are not call sites.
// @category RE
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.address.*;
import java.io.*;
import java.util.*;

public class DumpCallEdges extends GhidraScript {
    @Override
    public void run() throws Exception {
        PrintWriter out = new PrintWriter(new FileWriter(getScriptArgs()[0], true));
        String prog = currentProgram.getName();
        if (getScriptArgs().length > 1 && getScriptArgs()[1].equals("sites")) {
            for (ReCallWalk.Call c : ReCallWalk.walk(currentProgram, monitor)) {
                if (c.tail) continue;
                Function caller = getFunctionAt(c.function);
                Symbol s = c.target == null ? null : currentProgram.getSymbolTable().getPrimarySymbol(c.target);
                String callee = c.target == null ? "?" : s == null ? c.target.toString() : s.getName();
                out.println(prog + "\t" + caller.getName() + "\t" + callee + "\t" + (c.target == null ? "indirect" : "direct")
                    + "\t0x" + Long.toHexString(c.site.getOffset()) + "\t"
                    + (c.target == null ? "" : "0x" + Long.toHexString(c.target.getOffset())) + "\t" + c.kind);
            }
            out.close();
            return;
        }
        for (Function f : currentProgram.getFunctionManager().getFunctions(true)) {
            if (f.isExternal()) continue;
            Set<String> seen = new HashSet<>();
            InstructionIterator it = currentProgram.getListing().getInstructions(f.getBody(), true);
            while (it.hasNext()) {
                Instruction in = it.next();
                FlowType ft = in.getFlowType();
                if (!ft.isCall()) continue;
                boolean any = false;
                for (Reference r : in.getReferencesFrom()) {
                    if (!r.getReferenceType().isCall()) continue;
                    Symbol s = currentProgram.getSymbolTable().getPrimarySymbol(r.getToAddress());
                    String n = s == null ? r.getToAddress().toString() : s.getName();
                    if (seen.add("d" + n)) out.println(prog + "\t" + f.getName() + "\t" + n + "\tdirect");
                    any = true;
                }
                if (!any && ft.isComputed() && seen.add("i" + in.getAddress()))
                    out.println(prog + "\t" + f.getName() + "\t?\tindirect");
            }
        }
        out.close();
    }
}
