// Make the decompiler show every store to a board's command window.
//
// The decompiler treats a store to a plain address as a variable write and
// drops one that a later store to the same address overwrites, so a routine
// that sends ten words to one FIFO address decompiles to one. Memory the
// program declares volatile is never merged. This script declares address
// ranges volatile by creating, or marking, memory blocks over them. Run it
// before the decompile script (as a pre- or post-script, after the program is
// imported and before any decompile).
//
// Arguments: START-END[,START-END...]   hex addresses, END exclusive
//   MarkVolatileWindows.java 10000-11000,4000-8000
// A range that no block covers becomes a new uninitialized read/write block
// named volatile_<start>. A range inside an existing block marks that whole
// block volatile (a block cannot be split here), so give ranges that lie in
// no code or data block, or accept that the block as a whole becomes volatile.
//
// This fixes an address that is a constant: a window mapped at a fixed
// process address. A FIFO reached through a pointer loaded from a record
// (store through *(ctx+N)) is not merged by the decompiler, so it needs no
// range; check the count of stores in the decompile against the assembly.
// @category RE
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.mem.*;

public class MarkVolatileWindows extends GhidraScript {
    @Override
    public void run() throws Exception {
        String[] a = getScriptArgs();
        if (a.length < 1) { printerr("usage: START-END[,START-END...]"); return; }
        Memory mem = currentProgram.getMemory();
        for (String r : a[0].split(",")) {
            String[] se = r.split("-");
            long start = Long.parseUnsignedLong(se[0], 16), end = Long.parseUnsignedLong(se[1], 16);
            Address s = toAddr(start);
            MemoryBlock b = mem.getBlock(s);
            if (b == null) {
                if (mem.intersects(s, toAddr(end - 1))) {
                    printerr("MarkVolatileWindows: " + r + " overlaps a block without starting in one; split the range");
                    continue;
                }
                b = mem.createUninitializedBlock("volatile_" + Long.toHexString(start), s, end - start, false);
                b.setRead(true);
                b.setWrite(true);
            }
            b.setVolatile(true);
            println("MarkVolatileWindows: " + b.getName() + " " + b.getStart() + "-" + b.getEnd() + " volatile");
        }
    }
}
