/* Lay out the MMSC firmware image and name its symbols.
 *
 * Runs as a headless -preScript on a raw (BinaryLoader) import of mmscfw.bin
 * with language x86:LE:32:default. The raw import makes one block holding the
 * whole file at address zero; this script drops it and builds the real map
 * from the table tools/sysco/mmsc_aout.py writes with --tsv, so Ghidra and
 * the capstone loader share one parser:
 *
 *   text  file bytes at the entry address, read and execute
 *   data  file bytes after text, read and write
 *   bss   no bytes, read and write
 *
 * Every named routine becomes a function before analysis runs, so the
 * analysers disassemble from it and attribute calls to it. A name is applied
 * with the IMPORTED source: it came from the image's own table.
 *
 * Args: <image> <map.tsv>
 *
 * Ghidra script, Apache-2.0 like Ghidra itself.
 *
 * @category RE
 */

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.SourceType;

public class MmscAoutImport extends GhidraScript {

	@Override
	public void run() throws Exception {
		String[] args = getScriptArgs();
		if (args.length < 2) {
			throw new IllegalArgumentException(
				"usage: MmscAoutImport <image> <map.tsv>");
		}
		byte[] image = Files.readAllBytes(Paths.get(args[0]));
		List<String> lines = Files.readAllLines(Paths.get(args[1]),
			StandardCharsets.UTF_8);

		Memory mem = currentProgram.getMemory();
		for (MemoryBlock b : mem.getBlocks()) {
			mem.removeBlock(b, monitor);
		}

		List<String[]> syms = new ArrayList<>();
		for (String line : lines) {
			String[] f = line.split("\t");
			if (f[0].equals("SEG") && f.length == 5) {
				long addr = Long.decode(f[2]);
				int off = Integer.parseInt(f[3]);
				int size = Integer.parseInt(f[4]);
				MemoryBlock blk;
				if (off < 0) {
					blk = mem.createUninitializedBlock(f[1], address(addr),
						size, false);
				} else {
					blk = mem.createInitializedBlock(f[1], address(addr),
						new ByteArrayInputStream(image, off, size), size,
						monitor, false);
				}
				blk.setRead(true);
				blk.setWrite(!f[1].equals("text"));
				blk.setExecute(f[1].equals("text"));
			} else if (f[0].equals("SYM") && f.length == 6) {
				syms.add(f);
			}
		}

		int labelled = 0;
		int functions = 0;
		for (String[] f : syms) {
			Address at = address(Long.decode(f[1]));
			MemoryBlock block = mem.getBlock(at);
			if (block == null) {
				continue;
			}
			String name = f[3];
			// Local names repeat across objects; Ghidra numbers the repeats.
			currentProgram.getSymbolTable().createLabel(at, name,
				SourceType.IMPORTED);
			labelled++;
			if (block.isExecute() && f[4].equals("text")
					&& getFunctionAt(at) == null
					&& createFunction(at, name) != null) {
				functions++;
			}
		}
		println("MmscAoutImport: " + labelled + " labels, " + functions
			+ " functions");
	}

	private Address address(long value) {
		return currentProgram.getAddressFactory().getDefaultAddressSpace()
			.getAddress(value);
	}
}
