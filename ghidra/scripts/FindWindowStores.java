// List the stores (and loads) that reach a board's register window, as a
// tab-separated table. Two modes.
//
// Helper mode. A driver writes the board's registers through one helper
// (gfx_pio_write_32(address, value)) where address = a base pointer loaded
// from a state record + a constant. A cross-reference listing of the helper
// finds every call; the decompiler's constant folding turns each first
// argument into base+offset, so this needs no instruction patterns. Columns:
// program, function, call address, offset, stored value.
//
// Access mode (HELPER "-"). A driver or X module that dereferences the base
// directly has no helper to find. Every LOAD and STORE in every function is
// listed with its address folded into a base expression plus a constant
// offset. Columns: program, function, address, r or w, width in bytes, tag,
// base expression, offset, stored value, note.
//
//   tag   field   the base is one load from a record: *(p+0x338)
//         chain   the base is two or more nested loads, with or without a
//                 scaled index in between (an array of per-owner pointers
//                 walked with a slot number)
//         window  no base: a constant address, folded to its physical address
//                 when it is a kernel-segment (kseg0 or kseg1) or XKPHYS
//                 constant (note "kseg")
//   base expression
//         p stands for a value the decompiler could not trace further (an
//         argument, a register restored from the frame); *(X+0xN) is the word
//         loaded from X+0xN; [] marks a non-constant term added to X (an
//         index); 0xN is a constant. Example: *(*(*(p+0x1b4)[]+0x0)+0x0) is
//         the word at offset 0 of the record whose pointer sits in the array
//         at p+0x1b4, indexed by a slot number. The offset column is the
//         constant remainder after the last load.
//   Constant addresses that the decompiler turned into a plain variable (a
//   write to a global in the program's address space is a COPY, not a STORE)
//   are listed too, with tag window and note "var".
//
// Arguments: OUTFILE [HELPER [MINOFFSET [MAXOFFSET [TAGS [BASEREGEX]]]]]
//   HELPER     name of the store helper, or "-" for access mode
//                                               (default gfx_pio_write_32)
//   MINOFFSET  keep offsets >= this, hex        (default 0, keep everything)
//   MAXOFFSET  keep offsets <  this, hex        (default no limit)
//   TAGS       access mode: comma list of field, chain, window, other
//                                               (default field,chain,window)
//   BASEREGEX  access mode: Java regular expression the base expression must
//              match somewhere (default: any); ignored for tag window
// Offsets that do not fold to base+constant are printed as "?" with the
// expression in helper mode, so an unrecovered call is visible rather than
// dropped. A window mode run needs MINOFFSET and MAXOFFSET (or it lists every
// constant address in the program). Output is appended to OUTFILE so one run
// over many programs gives one table.
// @category RE
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.address.*;
import ghidra.program.model.pcode.*;
import java.io.*;
import java.util.*;
import java.util.regex.*;

public class FindWindowStores extends GhidraScript {
    // A folded address: base expression (null for none), non-constant index
    // term present, constant offset, load depth of the base, and whether the
    // value is a scaled term (a shift or multiply of something else).
    private static class Fold {
        final String base;
        final boolean idx;
        final long off;
        final int depth;
        final boolean scaled;
        final boolean globalLoad;   // base is a load from a constant address
        Fold(String base, boolean idx, long off, int depth, boolean scaled, boolean globalLoad) {
            this.base = base; this.idx = idx; this.off = off; this.depth = depth;
            this.scaled = scaled; this.globalLoad = globalLoad;
        }
        static Fold constant(long v) { return new Fold(null, false, v, 0, false, false); }
        static Fold unknown() { return new Fold("p", false, 0, 0, false, false); }
        boolean isConst() { return base == null && !idx; }
    }

    @Override
    public void run() throws Exception {
        String[] a = getScriptArgs();
        String helper = a.length > 1 ? a[1] : "gfx_pio_write_32";
        long min = a.length > 2 ? Long.parseUnsignedLong(a[2], 16) : 0;
        long max = a.length > 3 ? Long.parseUnsignedLong(a[3], 16) : Long.MAX_VALUE;
        boolean access = helper.equals("-");
        Set<String> tags = new HashSet<String>(Arrays.asList(
            (a.length > 4 ? a[4] : "field,chain,window").split(",")));
        Pattern want = a.length > 5 ? Pattern.compile(a[5]) : null;
        PrintWriter out = new PrintWriter(new FileWriter(a[0], true));
        DecompInterface di = new DecompInterface();
        di.openProgram(currentProgram);
        String prog = currentProgram.getName();
        for (Function f : currentProgram.getFunctionManager().getFunctions(true)) {
            if (f.isExternal() || f.isThunk()) continue;
            DecompileResults r = di.decompileFunction(f, 60, monitor);
            if (!r.decompileCompleted()) {
                out.println(prog + "\t" + f.getName() + "\t?\t?\tdecompile failed");
                continue;
            }
            HighFunction hf = r.getHighFunction();
            Iterator<PcodeOpAST> it = hf.getPcodeOps();
            while (it.hasNext()) {
                PcodeOpAST op = it.next();
                if (access) {
                    accessSites(out, prog, f, op, min, max, tags, want);
                    continue;
                }
                if (op.getOpcode() != PcodeOp.CALL) continue;
                Address t = op.getInput(0).getAddress();
                Function callee = getFunctionAt(t);
                if (callee == null || !callee.getName().equals(helper)) continue;
                if (op.getNumInputs() < 2) continue;
                Fold e = eval(op.getInput(1), 0);
                String off, expr = "";
                if (e.idx || e.base != null && e.depth == 0) {
                    off = "?"; expr = e.base + "[]+0x" + Long.toHexString(e.off);
                } else {
                    if (Long.compareUnsigned(e.off, min) < 0 || Long.compareUnsigned(e.off, max) >= 0) continue;
                    off = "0x" + Long.toHexString(e.off);
                }
                String val = "?";
                if (op.getNumInputs() > 2) {
                    Fold x = eval(op.getInput(2), 0);
                    if (x.isConst()) val = "0x" + Long.toHexString(x.off);
                }
                out.println(prog + "\t" + f.getName() + "\t" + op.getSeqnum().getTarget()
                    + "\t" + off + "\t" + val + (expr.isEmpty() ? "" : "\t" + expr));
            }
        }
        out.close();
    }

    private void accessSites(PrintWriter out, String prog, Function f, PcodeOpAST op, long min, long max,
                             Set<String> tags, Pattern want) {
        int oc = op.getOpcode();
        String fn = f.getName();
        if (oc != PcodeOp.STORE && oc != PcodeOp.LOAD) {
            if (!tags.contains("window")) return;
            // a constant address the decompiler turned into a plain variable
            Varnode o = op.getOutput();
            if (o != null && isVar(o) && inRange(phys(o.getOffset()), min, max)) {
                String val = oc == PcodeOp.COPY && op.getInput(0).isConstant()
                    ? "0x" + Long.toHexString(op.getInput(0).getOffset()) : "";
                out.println(prog + "\t" + fn + "\t" + op.getSeqnum().getTarget() + "\tw\t" + o.getSize()
                    + "\twindow\t\t0x" + Long.toHexString(phys(o.getOffset())) + "\t" + val + "\tvar");
            }
            for (int k = 0; k < op.getNumInputs(); k++) {
                Varnode in = op.getInput(k);
                if (in.getDef() == null && isVar(in) && inRange(phys(in.getOffset()), min, max))
                    out.println(prog + "\t" + fn + "\t" + op.getSeqnum().getTarget() + "\tr\t" + in.getSize()
                        + "\twindow\t\t0x" + Long.toHexString(phys(in.getOffset())) + "\t\tvar");
            }
            return;
        }
        Fold e = eval(op.getInput(1), 0);
        String tag, expr = "", note = "";
        long off = e.off;
        if (e.isConst()) {
            tag = "window";
            long p = phys(e.off);
            if (p != e.off) note = "kseg";
            off = p;
        } else {
            expr = e.base + (e.idx ? "[]" : "");
            tag = e.depth >= 2 ? "chain" : e.depth == 1 ? "field" : "other";
            if (want != null && !want.matcher(expr).find()) return;
        }
        if (!tags.contains(tag) || !inRange(off, min, max)) return;
        boolean st = oc == PcodeOp.STORE;
        int size = st ? op.getInput(2).getSize() : op.getOutput().getSize();
        String val = "";
        if (st) {
            Fold x = eval(op.getInput(2), 0);
            if (x.isConst()) val = "0x" + Long.toHexString(x.off);
        }
        out.println(prog + "\t" + fn + "\t" + op.getSeqnum().getTarget() + "\t" + (st ? "w" : "r") + "\t"
            + size + "\t" + tag + "\t" + expr + "\t0x" + Long.toHexString(off) + "\t" + val + "\t" + note);
    }

    private static boolean isVar(Varnode v) {
        return v.isAddress() && !v.getAddress().isRegisterAddress() && !v.getAddress().isStackAddress()
            && !v.getAddress().isUniqueAddress();
    }

    private static boolean inRange(long v, long min, long max) {
        return Long.compareUnsigned(v, min) >= 0 && Long.compareUnsigned(v, max) < 0;
    }

    // Physical address of a kernel-segment or XKPHYS constant; others unchanged.
    private static long phys(long v) {
        long hi32 = v >>> 32;
        long lo = v & 0xffffffffL;
        if ((hi32 == 0xffffffffL || hi32 == 0) && lo >= 0x80000000L && lo < 0xc0000000L) return lo & 0x1fffffffL;
        if ((v >>> 62) == 2) return v & 0xffffffffffL;
        return v;
    }

    // Fold a varnode to base expression + constant offset by walking its defining
    // operations: constants, copies, extensions, adds, constant shifts and
    // multiplies, and loads. Anything else is "p", an untraced value.
    private Fold eval(Varnode v, int depth) {
        if (v.isConstant()) return Fold.constant(v.getOffset());
        PcodeOp d = v.getDef();
        if (depth > 24 || d == null) return Fold.unknown();
        switch (d.getOpcode()) {
            case PcodeOp.COPY: case PcodeOp.CAST: case PcodeOp.INT_ZEXT: case PcodeOp.INT_SEXT:
                return eval(d.getInput(0), depth + 1);
            case PcodeOp.SUBPIECE:
                if (d.getInput(1).isConstant() && d.getInput(1).getOffset() == 0) return eval(d.getInput(0), depth + 1);
                return Fold.unknown();
            case PcodeOp.PTRSUB: case PcodeOp.INT_ADD: return add(eval(d.getInput(0), depth + 1), eval(d.getInput(1), depth + 1), 1);
            case PcodeOp.PTRADD: {
                Fold y = eval(d.getInput(1), depth + 1);
                long sz = d.getInput(2).getOffset();
                if (y.isConst()) y = Fold.constant(y.off * sz);
                else y = new Fold(y.base, y.idx, 0, y.depth, true, y.globalLoad);
                return add(eval(d.getInput(0), depth + 1), y, 1);
            }
            case PcodeOp.INT_SUB: {
                Fold x = eval(d.getInput(0), depth + 1), y = eval(d.getInput(1), depth + 1);
                if (y.isConst()) return add(x, Fold.constant(-y.off), 1);
                return Fold.unknown();
            }
            case PcodeOp.INT_LEFT: case PcodeOp.INT_MULT: {
                Fold x = eval(d.getInput(0), depth + 1), y = eval(d.getInput(1), depth + 1);
                if (x.isConst() && y.isConst())
                    return Fold.constant(d.getOpcode() == PcodeOp.INT_LEFT ? x.off << y.off : x.off * y.off);
                Fold t = x.isConst() ? y : x;
                return new Fold(t.base == null ? "p" : t.base, t.idx, 0, t.depth, true, t.globalLoad);
            }
            case PcodeOp.LOAD: {
                Fold a = eval(d.getInput(1), depth + 1);
                String inner = a.base == null ? "" : a.base + (a.idx ? "[]" : "");
                boolean global = a.isConst();
                String ex = "*(" + inner + (inner.isEmpty() ? "" : "+") + "0x" + Long.toHexString(a.off) + ")";
                return new Fold(ex, false, 0, a.depth + 1, false, global);
            }
            default:
                return Fold.unknown();
        }
    }

    // x + y. A constant folds into the offset. Two non-constants are a pointer
    // and an index; the scaled one is the index, else the deeper base, else the
    // base loaded from a record rather than from a global variable.
    private Fold add(Fold x, Fold y, int unused) {
        if (y.isConst()) return new Fold(x.base, x.idx, x.off + y.off, x.depth, x.scaled, x.globalLoad);
        if (x.isConst()) return new Fold(y.base, y.idx, x.off + y.off, y.depth, y.scaled, y.globalLoad);
        Fold ptr, ix;
        if (x.scaled != y.scaled) { ptr = x.scaled ? y : x; ix = x.scaled ? x : y; }
        else if (x.depth != y.depth) { ptr = x.depth > y.depth ? x : y; ix = x.depth > y.depth ? y : x; }
        else if (x.globalLoad != y.globalLoad) { ptr = x.globalLoad ? y : x; ix = x.globalLoad ? x : y; }
        else { ptr = x; ix = y; }
        return new Fold(ptr.base, true, ptr.off, ptr.depth, false, ptr.globalLoad);
    }
}
