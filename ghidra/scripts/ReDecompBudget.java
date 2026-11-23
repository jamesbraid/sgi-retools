// The decompiler's work limits, applied the same way by every script that decompiles. A plain helper class:
// scripts call open() once and run() per function. The three limits count work, not time, so what decompiles
// does not depend on how busy the host is; the timeout passed to run() is a ceiling against a hung
// decompiler, not a limit on normal work. A result is complete, partial (finished, but its C carries a
// warning that part of the body is missing or wrong) or failed, with the reason a budget limit, the ceiling
// or an error. Only a ceiling failure depends on time.
// The defaults are Ghidra's suggested limits. RE_DECOMPILE_BUDGET=INSTRUCTIONS,PAYLOAD_MB,JUMPTABLE_ENTRIES in
// the environment overrides them for a hand run.
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public final class ReDecompBudget {
    public static final int MAX_INSTRUCTIONS = DecompileOptions.SUGGESTED_MAX_INSTRUCTIONS;
    public static final int MAX_PAYLOAD_MB = DecompileOptions.SUGGESTED_MAX_PAYLOAD_BYTES;
    public static final int MAX_JUMPTABLE_ENTRIES = DecompileOptions.SUGGESTED_MAX_JUMPTABLE_ENTRIES;

    // The decompiler reports what it could not trust as block comments in the C it prints.
    private static final Pattern WARNING = Pattern.compile(
        "/\\*\\s*((?:WARNING|Warning|Unable|Could not|Bad instruction|Control flow|Removing unreachable|Restart)[^*]*(?:\\*(?!/)[^*]*)*)\\*/");
    // The warnings that mean part of the body is missing or wrong.
    private static final Pattern FLOW_LOSS = Pattern.compile(
        "Could not recover jumptable|Bad instruction|Removing unreachable block|Unimplemented instruction"
        + "|Truncating control flow|Treating indirect jump as call|Control flow ends");
    private static final Pattern BUDGET_MESSAGE = Pattern.compile("(?i)max.*(instruction|payload|jump)|exceed|too many|too large|limit");

    public final int maxInstructions;
    public final int maxPayloadMb;
    public final int maxJumpTableEntries;

    public ReDecompBudget(int maxInstructions, int maxPayloadMb, int maxJumpTableEntries) {
        this.maxInstructions = maxInstructions;
        this.maxPayloadMb = maxPayloadMb;
        this.maxJumpTableEntries = maxJumpTableEntries;
    }

    /** The suggested limits, or the ones in RE_DECOMPILE_BUDGET. */
    public static ReDecompBudget fromEnvironment() {
        String v = System.getenv("RE_DECOMPILE_BUDGET");
        if (v == null || v.isEmpty()) return new ReDecompBudget(MAX_INSTRUCTIONS, MAX_PAYLOAD_MB, MAX_JUMPTABLE_ENTRIES);
        String[] p = v.split(",");
        try {
            if (p.length != 3) throw new NumberFormatException("want three numbers");
            return new ReDecompBudget(Integer.parseInt(p[0].trim()), Integer.parseInt(p[1].trim()), Integer.parseInt(p[2].trim()));
        } catch (NumberFormatException e) {
            throw new IllegalArgumentException("RE_DECOMPILE_BUDGET is INSTRUCTIONS,PAYLOAD_MB,JUMPTABLE_ENTRIES, got \"" + v + "\"");
        }
    }

    /** An open decompiler on the program with the limits set, or null if it would not open. */
    public DecompInterface open(Program program) {
        DecompInterface di = new DecompInterface();
        // A new options object resets every other option too, so send one only for non-default limits.
        if (maxInstructions != MAX_INSTRUCTIONS || maxPayloadMb != MAX_PAYLOAD_MB
                || maxJumpTableEntries != MAX_JUMPTABLE_ENTRIES) {
            DecompileOptions options = new DecompileOptions();
            options.setMaxInstructions(maxInstructions);
            options.setMaxPayloadMBytes(maxPayloadMb);
            options.setMaxJumpTableEntries(maxJumpTableEntries);
            di.setOptions(options);
        }
        return di.openProgram(program) ? di : null;
    }

    public static final class Result {
        public final DecompileResults raw;      // null if the decompiler did not open
        public final String status;             // complete, partial or failed
        public final String reason;             // budget, ceiling or error when failed, else null
        public final String message;            // the decompiler's own message when failed, else null
        public final List<String> warnings;     // every warning in the C

        Result(DecompileResults raw, String status, String reason, String message, List<String> warnings) {
            this.raw = raw; this.status = status; this.reason = reason; this.message = message; this.warnings = warnings;
        }

        public boolean failed() {
            return status.equals("failed");
        }

        public boolean ceiling() {
            return "ceiling".equals(reason);
        }

        /** The C text, or null when failed. */
        public String c() {
            return failed() ? null : raw.getDecompiledFunction().getC();
        }
    }

    public Result run(DecompInterface di, Function f, int ceilingSeconds, TaskMonitor monitor) {
        return classify(di == null ? null : di.decompileFunction(f, ceilingSeconds, monitor));
    }

    public static Result classify(DecompileResults r) {
        List<String> warnings = new ArrayList<>();
        if (r == null) return new Result(null, "failed", "error", "decompiler did not open program", warnings);
        if (r.isTimedOut()) return new Result(r, "failed", "ceiling", "timeout", warnings);
        if (!r.decompileCompleted() || r.getDecompiledFunction() == null) {
            String m = String.valueOf(r.getErrorMessage());
            return new Result(r, "failed", BUDGET_MESSAGE.matcher(m).find() ? "budget" : "error", m, warnings);
        }
        Matcher w = WARNING.matcher(r.getDecompiledFunction().getC());
        boolean loss = false;
        while (w.find()) {
            String text = w.group(1).trim().replaceAll("\\s+", " ");
            warnings.add(text);
            loss |= FLOW_LOSS.matcher(text).find();
        }
        return new Result(r, loss ? "partial" : "complete", null, null, warnings);
    }
}
