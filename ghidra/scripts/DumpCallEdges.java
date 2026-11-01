// Dump the call edges of the program as tab-separated rows:
//   program, caller, callee, kind
// kind is "direct" for a call to a named function or external symbol and
// "indirect" for a register call Ghidra could not resolve (callee "?").
// Appends to the file named by the first argument, so a run over many
// programs gives one table; join them by name to walk a call graph that spans
// objects (a relocatable object names its other-object callees as externals).
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
