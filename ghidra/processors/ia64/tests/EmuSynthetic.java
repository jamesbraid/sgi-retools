// Run short instruction sequences in Ghidra's emulator and compare registers
// and memory with what the SDM says they must hold afterwards.
// Args: SPEC OUTFILE. SPEC lines, tab separated: name, address, steps,
// reg=hex,... to set, addr=hex,... memory qwords to set, reg=hex,... or
// mem:addr=hex,... expected after the steps. Writes "name PASS" or "name FAIL ...".
// @category IA64
import java.io.*;
import java.math.BigInteger;
import java.nio.file.*;
import java.util.*;

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.emulator.EmulatorHelper;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;

public class EmuSynthetic extends GhidraScript {
	static final BigInteger MASK = BigInteger.ONE.shiftLeft(64).subtract(BigInteger.ONE);

	@Override
	protected void run() throws Exception {
		String[] a = getScriptArgs();
		try (PrintWriter out = new PrintWriter(a[1])) {
			for (String line : Files.readAllLines(Paths.get(a[0]))) {
				if (line.isBlank()) {
					continue;
				}
				String[] f = line.split("\t", -1);
				out.println(f[0] + " " + runCase(f));
			}
		}
	}

	String runCase(String[] f) throws Exception {
		Address start = toAddr(f[1]);
		new DisassembleCommand(start, null, true).applyTo(currentProgram, monitor);
		EmulatorHelper emu = new EmulatorHelper(currentProgram);
		try {
			for (String kv : pairs(f[3])) {
				String[] p = kv.split("=");
				emu.writeRegister(p[0], new BigInteger(p[1], 16));
			}
			for (String kv : pairs(f[4])) {
				String[] p = kv.split("=");
				emu.writeMemory(toAddr(p[0]), qword(new BigInteger(p[1], 16)));
			}
			emu.writeRegister(emu.getPCRegister(), start.getOffset());
			for (int i = 0; i < Integer.parseInt(f[2]); i++) {
				if (!emu.step(monitor)) {
					return "FAIL emulator stopped at step " + i + ": " + emu.getLastError();
				}
			}
			StringBuilder bad = new StringBuilder();
			for (String kv : pairs(f[5])) {
				String[] p = kv.split("=");
				BigInteger want = new BigInteger(p[1], 16);
				BigInteger got;
				if (p[0].startsWith("mem:")) {
					byte[] b = emu.readMemory(toAddr(p[0].substring(4)), 8);
					got = new BigInteger(1, reverse(b));
				}
				else {
					got = emu.readRegister(p[0]);
				}
				if (!got.and(MASK).equals(want.and(MASK))) {
					bad.append(String.format(" %s=%x want %x", p[0], got.and(MASK), want.and(MASK)));
				}
			}
			return bad.length() == 0 ? "PASS" : "FAIL" + bad;
		}
		finally {
			emu.dispose();
		}
	}

	static List<String> pairs(String s) {
		return s.isEmpty() ? List.of() : Arrays.asList(s.split(","));
	}

	static byte[] qword(BigInteger v) {
		byte[] b = new byte[8];
		for (int i = 0; i < 8; i++) {
			b[i] = v.shiftRight(8 * i).byteValue();
		}
		return b;
	}

	static byte[] reverse(byte[] b) {
		byte[] r = new byte[b.length];
		for (int i = 0; i < b.length; i++) {
			r[i] = b[b.length - 1 - i];
		}
		return r;
	}
}
