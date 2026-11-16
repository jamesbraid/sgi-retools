/* Prepare an IA-64 PE32+ image (an EFI driver, elilo.efi) for analysis.
 *
 * Runs as a headless -preScript on a PE import: Ghidra's loader maps the sections, and this
 * applies the base relocations, resolves the entry point and the exports through their
 * function descriptors ({entry, gp}), sets r1 to the gp and makes a function at each
 * .pdata entry and at each descriptor in the image's data.
 * Args: none, or base=ADDR to move the image to a new base first.
 *
 * @category IA64
 */

import java.math.BigInteger;
import java.util.*;

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.Pointer64DataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;

public class IA64Pe extends GhidraScript {
	static final int DIR_EXPORT = 0, DIR_EXCEPTION = 3, DIR_BASERELOC = 5, DIR_GLOBALPTR = 8;
	static final int REL_DIR64 = 10;

	Memory mem;
	Address base;
	long opt;

	@Override
	protected void run() throws Exception {
		if (!currentProgram.getLanguage().getProcessor().toString().equals("IA64")
				|| !"Portable Executable (PE)".equals(currentProgram.getExecutableFormat())) {
			printerr("IA64Pe: not an IA-64 PE image");
			return;
		}
		mem = currentProgram.getMemory();
		for (String a : getScriptArgs()) {
			if (a.startsWith("base=")) {
				currentProgram.setImageBase(toAddr(Long.decode(a.substring(5))), true);
			}
		}
		base = currentProgram.getImageBase();
		long pe = mem.getInt(base.add(0x3c)) & 0xffffffffL;
		opt = pe + 24;
		long preferred = mem.getLong(base.add(opt + 24));
		long delta = base.getOffset() - preferred;
		Set<Long> sites = relocate(delta, preferred);

		long entryRva = mem.getInt(base.add(opt + 16)) & 0xffffffffL;
		Address entry = entryRva == 0 ? null : base.add(entryRva);
		BigInteger gp = null;
		if (entry != null && !isCode(entry) && sites.contains(entry.getOffset())) {
			gp = BigInteger.valueOf(mem.getLong(entry.add(8)));
		}
		else if (dir(DIR_GLOBALPTR)[0] != 0) {
			gp = BigInteger.valueOf(base.getOffset() + dir(DIR_GLOBALPTR)[0]);
		}
		if (gp != null) {
			for (MemoryBlock b : mem.getBlocks()) {
				if (b.isExecute()) {
					currentProgram.getProgramContext().setValue(currentProgram.getRegister("r1"),
						b.getStart(), b.getEnd(), gp);
				}
			}
		}

		int descriptors = 0;
		if (entry != null) {
			descriptors += descriptor(entry, "entry", sites) ? 1 : 0;
		}
		descriptors += exports(sites);
		for (long s : sites) {
			Address a = toAddr(s);
			if (!isCode(a) && descriptor(a, null, sites)) {
				descriptors++;
			}
		}
		long[] ex = dir(DIR_EXCEPTION);
		int pdata = 0;
		for (long o = 0; o + 12 <= ex[1] && ex[0] != 0; o += 12) {
			Address a = base.add(mem.getInt(base.add(ex[0] + o)) & 0xffffffffL);
			if (isCode(a)) {
				makeFunction(a, null);
				pdata++;
			}
		}
		println(String.format("IA64Pe: base %s, %d relocations (delta %#x), gp %s, %d descriptors, %d .pdata",
			base, sites.size(), delta, gp == null ? "-" : gp.toString(16), descriptors, pdata));
	}

	long[] dir(int i) throws Exception {
		long o = opt + 112 + 8 * i;
		return new long[] { mem.getInt(base.add(o)) & 0xffffffffL, mem.getInt(base.add(o + 4)) & 0xffffffffL };
	}

	boolean isCode(Address a) {
		MemoryBlock b = mem.getBlock(a);
		return b != null && b.isExecute();
	}

	// DIR64 fixups. The loader keeps the file's bytes, so add the delta to each site that holds a
	// preferred-base value (the gp points past the end of the image, so no size check). Returns every DIR64 site, as an offset in this program.
	Set<Long> relocate(long delta, long preferred) throws Exception {
		Set<Long> sites = new TreeSet<>();
		long[] rd = dir(DIR_BASERELOC);
		for (long o = 0; rd[0] != 0 && o + 8 <= rd[1];) {
			long page = mem.getInt(base.add(rd[0] + o)) & 0xffffffffL;
			long block = mem.getInt(base.add(rd[0] + o + 4)) & 0xffffffffL;
			if (block < 8) {
				break;
			}
			for (long e = 8; e + 2 <= block; e += 2) {
				int v = mem.getShort(base.add(rd[0] + o + e)) & 0xffff;
				if (v >> 12 != REL_DIR64) {
					continue;
				}
				Address site = base.add(page + (v & 0xfff));
				sites.add(site.getOffset());
				long val = mem.getLong(site);
				if (delta != 0 && Long.compareUnsigned(val - preferred, 1L << 32) < 0) {
					mem.setLong(site, val + delta);
				}
			}
			o += block;
		}
		return sites;
	}

	// ADDR holds {code, gp}: both words are relocated pointers, the first into code.
	boolean descriptor(Address a, String name, Set<Long> sites) throws Exception {
		if (!sites.contains(a.getOffset()) || !sites.contains(a.getOffset() + 8)) {
			return false;
		}
		Address code = toAddr(mem.getLong(a));
		if (!isCode(code) || isCode(toAddr(mem.getLong(a.add(8))))) {
			return false;
		}
		clearListing(a, a.add(15));
		createData(a, Pointer64DataType.dataType);
		createData(a.add(8), Pointer64DataType.dataType);
		makeFunction(code, name);
		if (name != null) {
			// Ghidra's loader labelled the descriptor with the name the function should have.
			for (Symbol s : currentProgram.getSymbolTable().getSymbols(a)) {
				if (s.getName().equals(name)) {
					s.setName(name + "_descriptor", SourceType.IMPORTED);
				}
			}
		}
		return true;
	}

	int exports(Set<Long> sites) throws Exception {
		long[] ed = dir(DIR_EXPORT);
		if (ed[0] == 0) {
			return 0;
		}
		Address e = base.add(ed[0]);
		long count = mem.getInt(e.add(24)) & 0xffffffffL;
		Address funcs = base.add(mem.getInt(e.add(28)) & 0xffffffffL);
		Address names = base.add(mem.getInt(e.add(32)) & 0xffffffffL);
		Address ords = base.add(mem.getInt(e.add(36)) & 0xffffffffL);
		int n = 0;
		for (long i = 0; i < count; i++) {
			int ord = mem.getShort(ords.add(2 * i)) & 0xffff;
			Address a = base.add(mem.getInt(funcs.add(4L * ord)) & 0xffffffffL);
			String name = cstring(base.add(mem.getInt(names.add(4 * i)) & 0xffffffffL));
			if (!isCode(a) && descriptor(a, name, sites)) {
				n++;
			}
			else if (isCode(a)) {
				makeFunction(a, name);
			}
		}
		return n;
	}

	String cstring(Address a) throws Exception {
		StringBuilder sb = new StringBuilder();
		for (byte b; (b = mem.getByte(a)) != 0; a = a.next()) {
			sb.append((char) b);
		}
		return sb.toString();
	}

	void makeFunction(Address a, String name) throws Exception {
		new DisassembleCommand(a, null, true).applyTo(currentProgram, monitor);
		Function f = getFunctionAt(a);
		if (f == null) {
			new CreateFunctionCmd(a).applyTo(currentProgram, monitor);
			f = getFunctionAt(a);
		}
		if (f != null && name != null) {
			f.setName(name, SourceType.IMPORTED);
		}
	}
}
