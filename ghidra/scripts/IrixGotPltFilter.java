// Make a working ELF copy whose MIPS GOT/PLT fixup metadata is absent. This
// avoids the Ghidra 12.1.3 MIPS loader's null-Data dereference. Only the tags of
// DT_MIPS_GOTSYM and DT_MIPS_LOCAL_GOTNO change, to DT_NULL; their values, file
// offsets and all other bytes are retained. The input is never modified.
//
// As a Ghidra script (for example, as a pre-script on a harmless import):
//   IrixGotPltFilter.java INPUT.elf OUTPUT.elf
// The class also has a main() so tests can run it with a JDK and Ghidra's jars.
// After importing OUTPUT.elf, run IrixGotPltRepair.java with INPUT.elf.
// @category RE
import ghidra.app.script.GhidraScript;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.file.*;
import java.util.*;

public class IrixGotPltFilter extends GhidraScript {
    static final long DT_NULL = 0;
    static final long DT_PLTGOT = 3;
    static final long DT_STRTAB = 5, DT_SYMTAB = 6, DT_STRSZ = 10, DT_SYMENT = 11;
    static final long DT_MIPS_LOCAL_GOTNO = 0x7000000aL;
    static final long DT_MIPS_SYMTABNO = 0x70000011L;
    static final long DT_MIPS_GOTSYM = 0x70000013L;
    static final long DT_MIPS_PLTGOT = 0x70000032L;
    private static final int PT_LOAD = 1, PT_DYNAMIC = 2;

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length != 2) throw new IllegalArgumentException("usage: INPUT.elf OUTPUT.elf");
        int count = filter(Paths.get(args[0]), Paths.get(args[1]));
        println("IrixGotPltFilter: " + args[0] + " -> " + args[1] + ", nulled " + count + " dynamic tag(s)");
    }

    public static void main(String[] args) throws Exception {
        if (args.length != 2) throw new IllegalArgumentException("usage: INPUT.elf OUTPUT.elf");
        int count = filter(Paths.get(args[0]), Paths.get(args[1]));
        System.out.println("IrixGotPltFilter: " + args[0] + " -> " + args[1]
            + ", nulled " + count + " dynamic tag(s)");
    }

    /** Copy input and replace only the two MIPS dynamic tags in the copy. */
    public static int filter(Path input, Path output) throws IOException {
        Path in = input.toAbsolutePath().normalize(), out = output.toAbsolutePath().normalize();
        if (in.equals(out)) throw new IOException("input and output must be different files");
        byte[] original = Files.readAllBytes(in);
        ElfMetadata elf = new ElfMetadata(original);
        byte[] copy = original.clone();
        int count = 0;
        for (DynamicEntry entry : elf.dynamics) {
            if (entry.tag != DT_MIPS_GOTSYM && entry.tag != DT_MIPS_LOCAL_GOTNO) continue;
            Arrays.fill(copy, Math.toIntExact(entry.fileOffset),
                Math.toIntExact(entry.fileOffset + elf.wordSize), (byte) 0);
            count++;
        }
        // CREATE_NEW also prevents an existing hard link from aliasing the input.
        Files.write(out, copy, StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE);
        return count;
    }

    static final class DynamicEntry {
        final long tag, value, fileOffset;
        DynamicEntry(long tag, long value, long fileOffset) {
            this.tag = tag; this.value = value; this.fileOffset = fileOffset;
        }
    }

    private static final class ProgramHeader {
        final int type;
        final long offset, virtualAddress, fileSize;
        ProgramHeader(int type, long offset, long virtualAddress, long fileSize) {
            this.type = type; this.offset = offset;
            this.virtualAddress = virtualAddress; this.fileSize = fileSize;
        }
    }

    /** Minimal, bounds-checked ELF program/dynamic metadata shared with repair. */
    static final class ElfMetadata {
        final Reader reader;
        final boolean elf64;
        final int wordSize;
        final List<ProgramHeader> programHeaders = new ArrayList<>();
        final List<DynamicEntry> dynamics = new ArrayList<>();

        ElfMetadata(byte[] bytes) throws IOException {
            reader = new Reader(bytes);
            if (bytes.length < 16 || bytes[0] != 0x7f || bytes[1] != 'E'
                || bytes[2] != 'L' || bytes[3] != 'F') throw new IOException("not an ELF file");
            if (bytes[4] != 1 && bytes[4] != 2) throw new IOException("unsupported ELF class " + bytes[4]);
            elf64 = bytes[4] == 2;
            wordSize = elf64 ? 8 : 4;
            if (bytes[5] == 1) reader.order = ByteOrder.LITTLE_ENDIAN;
            else if (bytes[5] == 2) reader.order = ByteOrder.BIG_ENDIAN;
            else throw new IOException("unsupported ELF byte order " + bytes[5]);
            int headerSize = elf64 ? 64 : 52, phSize = elf64 ? 56 : 32;
            reader.check(0, headerSize);
            long phoff = reader.word(elf64 ? 32 : 28, elf64);
            int phentsize = reader.u16(elf64 ? 54 : 42), phnum = reader.u16(elf64 ? 56 : 44);
            if (phnum == 0xffff) throw new IOException("extended ELF program-header counts are unsupported");
            if (phnum != 0 && phentsize < phSize)
                throw new IOException("short ELF program-header entry: " + phentsize);
            reader.check(phoff, Math.multiplyExact((long) phentsize, phnum));
            for (int i = 0; i < phnum; i++) {
                long p = phoff + (long) i * phentsize;
                int type = Math.toIntExact(reader.u32(p));
                long offset = reader.word(p + (elf64 ? 8 : 4), elf64);
                long virtual = reader.word(p + (elf64 ? 16 : 8), elf64);
                long size = reader.word(p + (elf64 ? 32 : 16), elf64);
                programHeaders.add(new ProgramHeader(type, offset, virtual, size));
            }
            for (ProgramHeader ph : programHeaders) {
                if (ph.type != PT_DYNAMIC) continue;
                reader.check(ph.offset, ph.fileSize);
                long entries = ph.fileSize / (2L * wordSize);
                for (long i = 0; i < entries; i++) {
                    long p = ph.offset + i * 2L * wordSize;
                    long tag = reader.word(p, elf64);
                    dynamics.add(new DynamicEntry(tag, reader.word(p + wordSize, elf64), p));
                    // DT_NULL terminates this segment; trailing words are padding,
                    // not dynamic entries and must remain byte-for-byte untouched.
                    if (tag == DT_NULL) break;
                }
            }
        }

        Long dynamicValue(long wanted) throws IOException {
            Long found = null;
            for (DynamicEntry entry : dynamics) {
                if (entry.tag != wanted) continue;
                if (found != null && found.longValue() != entry.value)
                    throw new IOException("conflicting values for dynamic tag 0x" + Long.toHexString(wanted));
                found = entry.value;
            }
            return found;
        }

        long fileOffset(long virtualAddress, long length) throws IOException {
            if (virtualAddress < 0 || length < 0)
                throw new IOException("negative ELF virtual range");
            for (ProgramHeader ph : programHeaders) {
                if (ph.type != PT_LOAD || virtualAddress < ph.virtualAddress) continue;
                long displacement = virtualAddress - ph.virtualAddress;
                if (displacement > ph.fileSize || length > ph.fileSize - displacement) continue;
                long result;
                try { result = Math.addExact(ph.offset, displacement); }
                catch (ArithmeticException e) { throw new IOException("ELF file offset overflow", e); }
                reader.check(result, length);
                return result;
            }
            throw new IOException("virtual range 0x" + Long.toHexString(virtualAddress)
                + " + 0x" + Long.toHexString(length) + " is not file-backed by a PT_LOAD");
        }

        String symbolName(long stringTable, long stringSize, long nameOffset) throws IOException {
            if (nameOffset < 0 || nameOffset >= stringSize)
                throw new IOException("symbol name offset outside DT_STRTAB");
            long start = fileOffset(stringTable, stringSize);
            long p = start + nameOffset, end = start + stringSize;
            long nul = p;
            while (nul < end && reader.bytes[Math.toIntExact(nul)] != 0) nul++;
            if (nul == end) throw new IOException("unterminated symbol name in DT_STRTAB");
            return new String(reader.bytes, Math.toIntExact(p), Math.toIntExact(nul - p),
                java.nio.charset.StandardCharsets.UTF_8);
        }

        Symbol symbol(long symtab, long syment, long index) throws IOException {
            int minimum = elf64 ? 24 : 16;
            if (syment < minimum) throw new IOException("short DT_SYMENT: " + syment);
            long offset;
            try { offset = symtab + Math.multiplyExact(syment, index); }
            catch (ArithmeticException e) { throw new IOException("dynamic symbol offset overflow", e); }
            long p = fileOffset(offset, minimum);
            long name = reader.u32(p);
            int info, shndx;
            if (elf64) { info = reader.u8(p + 4); shndx = reader.u16(p + 6); }
            else { info = reader.u8(p + 12); shndx = reader.u16(p + 14); }
            return new Symbol(name, info & 0xf, shndx);
        }
    }

    static final class Symbol {
        final long nameOffset;
        final int type, sectionIndex;
        Symbol(long nameOffset, int type, int sectionIndex) {
            this.nameOffset = nameOffset; this.type = type; this.sectionIndex = sectionIndex;
        }
    }

    private static final class Reader {
        final byte[] bytes;
        ByteOrder order;
        Reader(byte[] bytes) { this.bytes = bytes; }
        void check(long offset, long length) throws IOException {
            if (offset < 0 || length < 0 || offset > bytes.length || length > bytes.length - offset)
                throw new IOException("ELF range outside file: offset 0x" + Long.toHexString(offset)
                    + ", length 0x" + Long.toHexString(length));
        }
        int u8(long p) throws IOException { check(p, 1); return bytes[(int) p] & 0xff; }
        int u16(long p) throws IOException { check(p, 2); return ByteBuffer.wrap(bytes, (int) p, 2).order(order).getShort() & 0xffff; }
        long u32(long p) throws IOException { check(p, 4); return ByteBuffer.wrap(bytes, (int) p, 4).order(order).getInt() & 0xffffffffL; }
        long word(long p, boolean wide) throws IOException {
            check(p, wide ? 8 : 4);
            return wide ? ByteBuffer.wrap(bytes, (int) p, 8).order(order).getLong() : u32(p);
        }
    }
}
