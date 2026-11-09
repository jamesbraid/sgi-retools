import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Data;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.file.*;
import java.security.MessageDigest;
import java.util.*;
import java.util.function.Function;

/** Dependency-free regression assertions; run through tests/run.py. */
public class IrixGotPltScriptTest {
    private static final int DT_NULL = 0;
    private static final long DT_MIPS_LOCAL_GOTNO = 0x7000000aL;
    private static final long DT_MIPS_GOTSYM = 0x70000013L;

    public static void main(String[] args) throws Exception {
        Path dir = Paths.get(args[0]);
        for (int elfClass : new int[] { 2, 1 }) {
            ByteOrder order = elfClass == 2 ? ByteOrder.BIG_ENDIAN : ByteOrder.LITTLE_ENDIAN;
            String name = elfClass == 2 ? "ELF64-MSB" : "ELF32-LSB";
            Path input = dir.resolve("fixture-" + name + ".elf");
            Path output = dir.resolve("fixture-" + name + ".filtered.elf");
            byte[] bytes = fixture(elfClass, order);
            Files.write(input, bytes);
            String before = sha256(input);
            int replacements = IrixGotPltFilter.filter(input, output);
            assertEquals(2, replacements, name + " replacement count");
            assertEquals(before, sha256(input), name + " original SHA-256");
            IrixGotPltFilter.ElfMetadata metadata =
                new IrixGotPltFilter.ElfMetadata(Files.readAllBytes(input));
            assertEquals(0x12L, metadata.dynamicValue(DT_MIPS_GOTSYM), name + " GOTSYM stops at DT_NULL");
            assertEquals(3L, metadata.dynamicValue(DT_MIPS_LOCAL_GOTNO), name + " LOCAL_GOTNO stops at DT_NULL");
            byte[] actual = Files.readAllBytes(output);
            byte[] expected = bytes.clone();
            int dynamic = elfClass == 2 ? 0x100 : 0x80;
            int entry = elfClass == 2 ? 16 : 8;
            int tag = elfClass == 2 ? 8 : 4;
            Arrays.fill(expected, dynamic + entry, dynamic + entry + tag, (byte) 0);
            Arrays.fill(expected, dynamic + 2 * entry, dynamic + 2 * entry + tag, (byte) 0);
            assertArrayEquals(expected, actual, name + " byte-preserving filter");
            int changed = 0;
            for (int i = 0; i < bytes.length; i++) if (bytes[i] != actual[i]) changed++;
            System.out.println("PASS filter " + name + ": replacements=" + replacements
                + ", changedBytes=" + changed + ", postTerminatorCanaries=preserved, originalSha256=" + before);
        }

        List<String> log = new ArrayList<>();
        final int[] calls = { 0 };
        Function<Address, Data> nullCreator = address -> { calls[0]++; return null; };
        Data result = IrixGotPltRepair.createPointerSafely(ghidra.program.model.address.Address.NO_ADDRESS, 8, nullCreator, log::add);
        assertEquals(null, result, "null Data result is propagated");
        assertEquals(1, calls[0], "null-safe creator call count");
        assertEquals(1, log.size(), "null Data skip is logged exactly once");
        if (!log.get(0).contains("createData returned null"))
            throw new AssertionError("missing null Data explanation: " + log);
        System.out.println("PASS repair null Data: no getValue call; " + log.get(0));
        testExternalLinkageCollisionAndRollback();

        Path same = dir.resolve("fixture-ELF64-MSB.elf");
        try {
            IrixGotPltFilter.filter(same, same);
            throw new AssertionError("in-place filtering was not rejected");
        } catch (IOException expected) {
            System.out.println("PASS in-place input rejected: " + expected.getMessage());
        }
    }

    private static void testExternalLinkageCollisionAndRollback() {
        Address target = Address.NO_ADDRESS;
        FakeLinkage collision = new FakeLinkage();
        FakeFunction ordinary = new FakeFunction("ordinary");
        collision.functions.put(target, ordinary);
        List<String> collisionLog = new ArrayList<>();
        assertEquals(IrixGotPltRepair.LinkageResult.SKIPPED,
            IrixGotPltRepair.linkExternalSafely("ordinary", target, "collision-test", collision, collisionLog::add),
            "ordinary function collision");
        assertEquals(0, collision.thunkCreates, "collision must not create a thunk");
        assertEquals(0, collision.externalCreates, "collision must not create an external");
        assertEquals(false, ordinary.thunk, "ordinary function must remain ordinary");

        FakeLinkage failure = new FakeLinkage();
        failure.failSet = true;
        List<String> failureLog = new ArrayList<>();
        assertEquals(IrixGotPltRepair.LinkageResult.SKIPPED,
            IrixGotPltRepair.linkExternalSafely("forced", target, "forced-failure-test", failure, failureLog::add),
            "forced setThunkedFunction failure");
        assertEquals(false, failure.functions.containsKey(target), "failed thunk must be rolled back");
        assertEquals(false, failure.externals.containsKey("forced"), "failed external must be rolled back");
        assertEquals(1, failure.thunkRemovals, "thunk rollback count");
        assertEquals(1, failure.externalRemovals, "external rollback count");
        if (!failureLog.toString().contains("forced set failure"))
            throw new AssertionError("forced failure was not logged: " + failureLog);

        FakeLinkage success = new FakeLinkage();
        assertEquals(IrixGotPltRepair.LinkageResult.LINKED,
            IrixGotPltRepair.linkExternalSafely("good", target, "success-test", success, message -> { }),
            "valid new thunk linkage");
        assertEquals(Arrays.asList("createThunk", "createExternal", "setThunk"), success.events,
            "external must be created only after a suitable new thunk exists");
        System.out.println("PASS linkage ordinary-collision and forced-failure rollback");
    }

    private static final class FakeFunction {
        final String name;
        boolean external, thunk;
        FakeFunction linked;
        FakeFunction(String name) { this.name = name; }
    }

    private static final class FakeLinkage implements IrixGotPltRepair.LinkageOps<FakeFunction, FakeFunction> {
        final Map<Address, FakeFunction> functions = new HashMap<>();
        final Map<String, FakeFunction> externals = new HashMap<>();
        final List<String> events = new ArrayList<>();
        boolean failSet;
        int thunkCreates, externalCreates, thunkRemovals, externalRemovals;
        public FakeFunction existingFunction(Address target) { return functions.get(target); }
        public boolean isThunk(FakeFunction function) { return function.thunk; }
        public FakeFunction thunkedFunction(FakeFunction function) { return function.linked; }
        public boolean isExternal(FakeFunction function) { return function.external; }
        public String functionName(FakeFunction function) { return function.name; }
        public FakeFunction createThunk(String name, Address target) {
            events.add("createThunk"); thunkCreates++;
            FakeFunction created = new FakeFunction(name); functions.put(target, created); return created;
        }
        public void removeThunk(Address target, FakeFunction thunk) { thunkRemovals++; functions.values().remove(thunk); }
        public boolean externalExists(String name) { return externals.containsKey(name); }
        public FakeFunction createExternal(String name) {
            events.add("createExternal"); externalCreates++;
            FakeFunction created = new FakeFunction(name); created.external = true;
            externals.put(name, created); return created;
        }
        public FakeFunction externalFunction(FakeFunction external) { return external; }
        public void setThunkedFunction(FakeFunction thunk, FakeFunction external) {
            events.add("setThunk");
            if (failSet) throw new RuntimeException("forced set failure");
            thunk.thunk = true; thunk.linked = external;
        }
        public void removeExternal(String name, FakeFunction external) {
            externalRemovals++; externals.values().remove(external);
        }
    }

    private static byte[] fixture(int elfClass, ByteOrder order) {
        ByteBuffer b = ByteBuffer.allocate(0x180).order(order);
        b.put(0, (byte) 0x7f).put(1, (byte) 'E').put(2, (byte) 'L').put(3, (byte) 'F');
        b.put(4, (byte) elfClass).put(5, (byte) (order == ByteOrder.BIG_ENDIAN ? 2 : 1)).put(6, (byte) 1);
        int dynamic = elfClass == 2 ? 0x100 : 0x80;
        int phnum = 2;
        if (elfClass == 2) {
            put(b, 16, 2, 2); put(b, 18, 8, 2); put(b, 20, 1, 4);
            put(b, 24, 0, 8); put(b, 32, 64, 8); put(b, 40, 0, 8);
            put(b, 48, 0x20000000L, 4); put(b, 52, 64, 2); put(b, 54, 56, 2); put(b, 56, phnum, 2);
            ph64(b, 64, 1, 0, 0x10000000L, b.capacity(), 4);
            ph64(b, 120, 2, dynamic, 0x10000000L + dynamic, 6 * 16, 4);
            dyn(b, dynamic, 1, 7, 8);
            dyn(b, dynamic + 16, DT_MIPS_GOTSYM, 0x12, 8);
            dyn(b, dynamic + 32, DT_MIPS_LOCAL_GOTNO, 3, 8);
            dyn(b, dynamic + 48, DT_NULL, 0x55aa, 8);
            dyn(b, dynamic + 64, DT_MIPS_GOTSYM, 0x12345678, 8);
            dyn(b, dynamic + 80, DT_MIPS_LOCAL_GOTNO, 0x76543210, 8);
        } else {
            put(b, 16, 2, 2); put(b, 18, 8, 2); put(b, 20, 1, 4);
            put(b, 24, 0, 4); put(b, 28, 52, 4); put(b, 32, 0, 4);
            put(b, 36, 0, 4); put(b, 40, 52, 2); put(b, 42, 32, 2); put(b, 44, phnum, 2);
            ph32(b, 52, 1, 0, 0x10000000L, b.capacity(), 4);
            ph32(b, 84, 2, dynamic, 0x10000000L + dynamic, 6 * 8, 4);
            dyn(b, dynamic, 1, 7, 4);
            dyn(b, dynamic + 8, DT_MIPS_GOTSYM, 0x12, 4);
            dyn(b, dynamic + 16, DT_MIPS_LOCAL_GOTNO, 3, 4);
            dyn(b, dynamic + 24, DT_NULL, 0x55aa, 4);
            dyn(b, dynamic + 32, DT_MIPS_GOTSYM, 0x12345678, 4);
            dyn(b, dynamic + 40, DT_MIPS_LOCAL_GOTNO, 0x76543210, 4);
        }
        return b.array();
    }

    private static void ph64(ByteBuffer b, int p, int type, long off, long base, long size, int flags) {
        put(b, p, type, 4); put(b, p + 4, flags, 4); put(b, p + 8, off, 8);
        put(b, p + 16, base + off, 8); put(b, p + 24, base + off, 8);
        put(b, p + 32, size, 8); put(b, p + 40, size, 8); put(b, p + 48, 0x1000, 8);
    }

    private static void ph32(ByteBuffer b, int p, int type, long off, long base, long size, int flags) {
        put(b, p, type, 4); put(b, p + 4, off, 4); put(b, p + 8, base + off, 4);
        put(b, p + 12, base + off, 4); put(b, p + 16, size, 4); put(b, p + 20, size, 4);
        put(b, p + 24, flags, 4); put(b, p + 28, 0x1000, 4);
    }

    private static void dyn(ByteBuffer b, int p, long tag, long value, int word) {
        put(b, p, tag, word); put(b, p + word, value, word);
    }

    private static void put(ByteBuffer b, int p, long value, int size) {
        for (int i = 0; i < size; i++) {
            int shift = 8 * (b.order() == ByteOrder.BIG_ENDIAN ? size - 1 - i : i);
            b.put(p + i, (byte) (value >>> shift));
        }
    }

    private static String sha256(Path path) throws Exception {
        byte[] digest = MessageDigest.getInstance("SHA-256").digest(Files.readAllBytes(path));
        StringBuilder out = new StringBuilder();
        for (byte v : digest) out.append(String.format("%02x", v));
        return out.toString();
    }

    private static void assertEquals(Object expected, Object actual, String label) {
        if (!Objects.equals(expected, actual))
            throw new AssertionError(label + ": expected " + expected + ", got " + actual);
    }

    private static void assertArrayEquals(byte[] expected, byte[] actual, String label) {
        if (!Arrays.equals(expected, actual)) {
            for (int i = 0; i < Math.min(expected.length, actual.length); i++)
                if (expected[i] != actual[i])
                    throw new AssertionError(label + ": first unexpected difference at 0x" + Integer.toHexString(i));
            throw new AssertionError(label + ": length differs");
        }
    }
}
