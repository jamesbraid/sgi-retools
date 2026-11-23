// @category RE
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.listing.*;
import java.io.PrintWriter;
public class BudgetProbe extends GhidraScript {
    protected void run() throws Exception {
        ReDecompBudget b = ReDecompBudget.fromEnvironment();
        DecompInterface di = b.open(currentProgram);
        try (PrintWriter out = new PrintWriter(getScriptArgs()[0])) {
            for (Function f : currentProgram.getFunctionManager().getFunctions(true)) {
                ReDecompBudget.Result r = b.run(di, f, 60, monitor);
                out.println(f.getName() + "\t" + r.status + "\t" + r.reason + "\t" + r.message + "\t" + r.warnings);
            }
        }
    }
}
