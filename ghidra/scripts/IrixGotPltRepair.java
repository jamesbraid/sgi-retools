// Restore MIPS GOT/PLT markup after importing an IrixGotPltFilter working copy.
// Supply the ORIGINAL, unmodified ELF as the only argument:
//   -postScript IrixGotPltRepair.java ORIGINAL.elf
// Pointer creation is checked before Data.getValue(), and all file, memory,
// symbol-table and string-table accesses are bounds checked. Every skipped GOT
// entry or external linkage is logged. No symbol target is invented.
// @category RE
import ghidra.app.script.GhidraScript;
import ghidra.app.util.opinion.ElfLoader;
import ghidra.program.model.address.*;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.symbol.*;
import java.nio.file.*;
import java.util.function.Consumer;
import java.util.function.Function;

public class IrixGotPltRepair extends GhidraScript {
    private static final int STT_FUNC = 2;

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length != 1) throw new IllegalArgumentException("usage: ORIGINAL.elf");
        if (currentProgram == null) throw new IllegalStateException("no imported program");
        IrixGotPltFilter.ElfMetadata elf =
            new IrixGotPltFilter.ElfMetadata(Files.readAllBytes(Paths.get(args[0])));
        Long localCount = required(elf, IrixGotPltFilter.DT_MIPS_LOCAL_GOTNO);
        Long gotSymbol = required(elf, IrixGotPltFilter.DT_MIPS_GOTSYM);
        Long symbolCount = required(elf, IrixGotPltFilter.DT_MIPS_SYMTABNO);
        Long got = elf.dynamicValue(IrixGotPltFilter.DT_PLTGOT);
        if (got == null) got = elf.dynamicValue(IrixGotPltFilter.DT_MIPS_PLTGOT);
        Long symtab = required(elf, IrixGotPltFilter.DT_SYMTAB);
        Long strtab = required(elf, IrixGotPltFilter.DT_STRTAB);
        Long strsz = required(elf, IrixGotPltFilter.DT_STRSZ);
        Long syment = required(elf, IrixGotPltFilter.DT_SYMENT);
        if (got == null) { println("IrixGotPltRepair: SKIP all: no DT_PLTGOT/DT_MIPS_PLTGOT"); return; }
        if (localCount < 0 || gotSymbol < 0 || symbolCount < gotSymbol) {
            println("IrixGotPltRepair: SKIP all: invalid MIPS GOT/symbol counts"); return;
        }
        long globalCount = symbolCount - gotSymbol;
        long total;
        try { total = Math.addExact(localCount, globalCount); }
        catch (ArithmeticException e) { println("IrixGotPltRepair: SKIP all: GOT count overflow"); return; }
        int pointerSize = elf.wordSize;
        if (pointerSize != currentProgram.getDefaultPointerSize()) {
            println("IrixGotPltRepair: SKIP all: ELF/program pointer sizes differ"); return;
        }
        Long oldBase = ElfLoader.getElfOriginalImageBase(currentProgram);
        long imageShift = currentProgram.getImageBase().getOffset() - (oldBase == null ? 0 : oldBase);
        AddressSpace space = currentProgram.getAddressFactory().getDefaultAddressSpace();
        int pointers = 0, linkages = 0, skipped = 0;
        for (long index = 0; index < total; index++) {
            monitor.checkCancelled();
            Address entry = null;
            try {
                long offset = Math.addExact(got, Math.multiplyExact(index, pointerSize));
                entry = space.getAddress(Math.addExact(offset, imageShift));
                if (!validPointerMemory(entry, pointerSize)) {
                    skipped++;
                    skip("GOT[" + index + "] at " + entry + ": pointer is outside one initialized memory block");
                    continue;
                }
                adjustNonZero(entry, pointerSize, imageShift);
                Data data = createPointerSafely(entry, pointerSize, address -> {
                    try { return createData(address, PointerDataType.dataType); }
                    catch (ghidra.program.model.util.CodeUnitInsertionException e) {
                        throw new RuntimeException("createData failed: " + e.getMessage(), e);
                    }
                }, this::println);
                if (data == null) { skipped++; continue; }
                pointers++;
                if (index < localCount) continue;
                long symbolIndex = gotSymbol + (index - localCount);
                IrixGotPltFilter.Symbol symbol = elf.symbol(symtab, syment, symbolIndex);
                if (symbol.type != STT_FUNC || symbol.sectionIndex != 0) continue;
                String name = elf.symbolName(strtab, strsz, symbol.nameOffset);
                if (name.isEmpty()) {
                    skipped++; skip("GOT[" + index + "] symbol[" + symbolIndex + "]: empty external name");
                    continue;
                }
                Object value = data.getValue(); // data was explicitly checked for null above
                if (!(value instanceof Address)) {
                    skipped++; skip("GOT[" + index + "] " + name + ": pointer value is not an address: " + value);
                    continue;
                }
                if (createExternalLinkage(name, (Address) value, entry)) linkages++;
                else skipped++;
            } catch (Exception e) {
                skipped++;
                skip("GOT[" + index + "]" + (entry == null ? "" : " at " + entry)
                    + ": " + e.getClass().getSimpleName() + ": " + e.getMessage());
            }
        }
        println("IrixGotPltRepair: pointers=" + pointers + ", externalLinkages=" + linkages
            + ", skipped=" + skipped + ", totalGotEntries=" + total);
    }

    private Long required(IrixGotPltFilter.ElfMetadata elf, long tag) throws Exception {
        Long value = elf.dynamicValue(tag);
        if (value == null) throw new IllegalArgumentException("missing required dynamic tag 0x" + Long.toHexString(tag));
        return value;
    }

    private boolean validPointerMemory(Address address, int pointerSize) {
        MemoryBlock block = currentProgram.getMemory().getBlock(address);
        if (block == null || !block.isInitialized()) return false;
        long remaining = block.getEnd().getOffset() - address.getOffset();
        return remaining >= pointerSize - 1L;
    }

    private void adjustNonZero(Address address, int pointerSize, long imageShift) throws Exception {
        if (imageShift == 0) return;
        Memory memory = currentProgram.getMemory();
        if (pointerSize == 8) {
            long value = memory.getLong(address);
            if (value != 0) memory.setLong(address, Math.addExact(value, imageShift));
        } else {
            long value = memory.getInt(address) & 0xffffffffL;
            if (value != 0) memory.setInt(address, (int) Math.addExact(value, imageShift));
        }
    }

    /** Null-safe by design: a failed createData is logged, never dereferenced. */
    static Data createPointerSafely(Address address, int pointerSize,
            Function<Address, Data> creator, Consumer<String> logger) {
        String where = "GOT/PLT pointer at " + address;
        if (address == null || (pointerSize != 4 && pointerSize != 8)) {
            logger.accept("IrixGotPltRepair: SKIP " + where + ": invalid address or pointer size " + pointerSize);
            return null;
        }
        final Data data;
        try { data = creator.apply(address); }
        catch (RuntimeException e) {
            logger.accept("IrixGotPltRepair: SKIP " + where + ": createData threw "
                + e.getClass().getSimpleName() + ": " + e.getMessage());
            return null;
        }
        if (data == null) {
            logger.accept("IrixGotPltRepair: SKIP " + where + ": createData returned null");
            return null;
        }
        return data;
    }

    enum LinkageResult { LINKED, ALREADY_LINKED, SKIPPED }

    /** Program-independent linkage operations, also implemented by the focused tests. */
    interface LinkageOps<T, E> {
        T existingFunction(Address target) throws Exception;
        boolean isThunk(T function) throws Exception;
        T thunkedFunction(T function) throws Exception;
        boolean isExternal(T function) throws Exception;
        String functionName(T function) throws Exception;
        T createThunk(String name, Address target) throws Exception;
        void removeThunk(Address target, T thunk) throws Exception;
        boolean externalExists(String name) throws Exception;
        E createExternal(String name) throws Exception;
        T externalFunction(E external) throws Exception;
        void setThunkedFunction(T thunk, T external) throws Exception;
        void removeExternal(String name, E external) throws Exception;
    }

    /**
     * Link only a new thunk or an existing matching external thunk. Ordinary
     * functions and partially/mismatched thunks are collisions, not repair
     * candidates. Every object created by a failed attempt is rolled back.
     */
    static <T, E> LinkageResult linkExternalSafely(String name, Address target, String context,
            LinkageOps<T, E> ops, Consumer<String> logger) {
        T createdThunk = null;
        E createdExternal = null;
        boolean thunkAttempted = false, externalAttempted = false, externalExisted = false, success = false;
        try {
            T existing = ops.existingFunction(target);
            if (existing != null) {
                if (!ops.isThunk(existing)) {
                    logger.accept("IrixGotPltRepair: SKIP " + context + ": ordinary function collision at " + target);
                    return LinkageResult.SKIPPED;
                }
                T linked = ops.thunkedFunction(existing);
                if (linked == null || !ops.isExternal(linked) || !name.equals(ops.functionName(linked))) {
                    logger.accept("IrixGotPltRepair: SKIP " + context + ": existing thunk collision at " + target);
                    return LinkageResult.SKIPPED;
                }
                success = true;
                return LinkageResult.ALREADY_LINKED;
            }
            thunkAttempted = true;
            createdThunk = ops.createThunk(name, target);
            if (createdThunk == null) throw new IllegalStateException("Ghidra returned no new thunk");
            externalExisted = ops.externalExists(name);
            externalAttempted = true;
            createdExternal = ops.createExternal(name);
            T externalFunction = createdExternal == null ? null : ops.externalFunction(createdExternal);
            if (externalFunction == null) throw new IllegalStateException("Ghidra returned no external function");
            ops.setThunkedFunction(createdThunk, externalFunction);
            success = true;
            return LinkageResult.LINKED;
        } catch (Exception e) {
            logger.accept("IrixGotPltRepair: SKIP " + context + ": linkage failed: "
                + e.getClass().getSimpleName() + ": " + e.getMessage());
            return LinkageResult.SKIPPED;
        } finally {
            if (!success) {
                if (thunkAttempted) {
                    try { ops.removeThunk(target, createdThunk); }
                    catch (Exception e) {
                        logger.accept("IrixGotPltRepair: SKIP " + context + ": thunk rollback failed: " + e.getMessage());
                    }
                }
                if (externalAttempted && !externalExisted) {
                    try { ops.removeExternal(name, createdExternal); }
                    catch (Exception e) {
                        logger.accept("IrixGotPltRepair: SKIP " + context + ": external rollback failed: " + e.getMessage());
                    }
                }
            }
        }
    }

    private boolean createExternalLinkage(String name, Address target, Address gotEntry) {
        MemoryBlock block = currentProgram.getMemory().getBlock(target);
        if (block == null || !block.isInitialized() || !block.isExecute()) {
            skip("GOT entry " + gotEntry + " " + name + ": target " + target
                + " is unrelocated/unresolved or otherwise invalid (not initialized executable memory)");
            return false;
        }
        FunctionManager functions = currentProgram.getFunctionManager();
        ExternalManager externals = currentProgram.getExternalManager();
        LinkageOps<ghidra.program.model.listing.Function, ExternalLocation> ops =
            new LinkageOps<ghidra.program.model.listing.Function, ExternalLocation>() {
                public ghidra.program.model.listing.Function existingFunction(Address address) {
                    return functions.getFunctionAt(address);
                }
                public boolean isThunk(ghidra.program.model.listing.Function function) { return function.isThunk(); }
                public ghidra.program.model.listing.Function thunkedFunction(
                        ghidra.program.model.listing.Function function) { return function.getThunkedFunction(false); }
                public boolean isExternal(ghidra.program.model.listing.Function function) { return function.isExternal(); }
                public String functionName(ghidra.program.model.listing.Function function) { return function.getName(); }
                public ghidra.program.model.listing.Function createThunk(String symbol, Address address)
                        throws Exception {
                    return functions.createFunction(symbol, address, new AddressSet(address, address), SourceType.IMPORTED);
                }
                public void removeThunk(Address address, ghidra.program.model.listing.Function thunk) {
                    ghidra.program.model.listing.Function candidate =
                        thunk == null ? functions.getFunctionAt(address) : thunk;
                    if (candidate != null && !functions.removeFunction(candidate.getEntryPoint()))
                        throw new IllegalStateException("could not remove new thunk at " + candidate.getEntryPoint());
                }
                public boolean externalExists(String symbol) {
                    return !externals.getExternalLocations(Library.UNKNOWN, symbol).isEmpty();
                }
                public ExternalLocation createExternal(String symbol) throws Exception {
                    return externals.addExtFunction(Library.UNKNOWN, symbol, null, SourceType.IMPORTED);
                }
                public ghidra.program.model.listing.Function externalFunction(ExternalLocation external) {
                    return external.getFunction();
                }
                public void setThunkedFunction(ghidra.program.model.listing.Function thunk,
                        ghidra.program.model.listing.Function external) { thunk.setThunkedFunction(external); }
                public void removeExternal(String symbol, ExternalLocation external) {
                    ExternalLocation candidate = external;
                    if (candidate == null)
                        for (ExternalLocation item : externals.getExternalLocations(Library.UNKNOWN, symbol)) {
                            candidate = item; break;
                        }
                    ghidra.program.model.listing.Function function =
                        candidate == null ? null : candidate.getFunction();
                    if (function != null && !functions.removeFunction(function.getEntryPoint()))
                        throw new IllegalStateException("could not remove new external " + symbol);
                }
            };
        String context = "GOT entry " + gotEntry + " " + name;
        LinkageResult result = linkExternalSafely(name, target, context, ops, this::println);
        if (result == LinkageResult.LINKED)
            println("IrixGotPltRepair: linked " + gotEntry + " -> " + target + " " + name);
        else if (result == LinkageResult.ALREADY_LINKED)
            println("IrixGotPltRepair: already linked " + gotEntry + " -> " + target + " " + name);
        return result != LinkageResult.SKIPPED;
    }

    private void skip(String detail) { println("IrixGotPltRepair: SKIP " + detail); }
}
