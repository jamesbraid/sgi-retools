// Virtual to physical address for the processors the RE workspaces read. A plain helper class: scripts call
// RePhysical.toPhysical, nothing runs it. An address that is not a fixed window of the physical space is
// returned unchanged.
import ghidra.program.model.lang.Processor;

public final class RePhysical {
    private RePhysical() {}

    // MIPS: kseg0 and kseg1 (as a sign-extended 32-bit address or a 32-bit one), and XKPHYS.
    public static long mips(long v) {
        long hi32 = v >>> 32;
        long lo = v & 0xffffffffL;
        if ((hi32 == 0xffffffffL || hi32 == 0) && lo >= 0x80000000L && lo < 0xc0000000L) return lo & 0x1fffffffL;
        if ((v >>> 62) == 2) return v & 0xffffffffffL;
        return v;
    }

    // IA-64: the identity-mapped regions 6 (uncached) and 7 (cached), and the bit-63 uncached alias a
    // physical-mode access uses. The alias is taken only when bits 62..50 are zero, so a region 4 or 5
    // address is not mistaken for it.
    public static long ia64(long v) {
        long region = v >>> 61;
        if (region == 6 || region == 7) return v & ((1L << 61) - 1);
        if ((v >>> 63) == 1 && ((v >>> 50) & 0x1fffL) == 0) return v & ((1L << 50) - 1);
        return v;
    }

    public static long toPhysical(Processor processor, long v) {
        String name = processor.toString();
        if (name.equals("MIPS")) return mips(v);
        if (name.equals("IA64")) return ia64(v);
        return v;
    }
}
