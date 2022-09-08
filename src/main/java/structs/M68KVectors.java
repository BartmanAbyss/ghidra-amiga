package structs;

import java.io.IOException;

import ghidra.app.util.bin.StructConverter;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.FunctionDefinitionDataType;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;
import ghidra.util.exception.DuplicateNameException;

public class M68KVectors implements StructConverter {

    @Override
    public DataType toDataType() throws DuplicateNameException, IOException {
        Structure s = new StructureDataType("M68KExceptionVectors", 0);
        DataType addr = new PointerDataType(VOID);
        FunctionDefinitionDataType func = new FunctionDefinitionDataType("ExceptionHandler");
        func.setReturnType(VOID);
        DataType funcAddr = new PointerDataType(func);

        int prevIndex = 0;
        for (Vector v : Vector.values()) {
            for (int i = prevIndex + 1; i < v.index; i++) {
                // Insert placeholder fields for any indices that are reserved
                // or otherwise unassigned.
                s.add(DWORD, 4, String.format("reserved%02x", i), "(reserved)");
            }
            DataType type = v.justAddr ? addr : funcAddr;
            s.add(type, 4, v.name, v.desc);
            prevIndex = v.index;
        }

        for (int i = prevIndex + 1; i < 64; i++) {
            s.add(DWORD, 4, String.format("reserved%02x", i), "(reserved)");
        }

        // We intentionally don't include the user vectors here because Amigas
        // use autovectoring and so these addresses tend to be used as general
        // chip memory rather than as vectors.

        return s;
    }

    static enum Vector {
        resetSP(0, "reset_sp", "Stack Pointer at Reset", true),
        resetPC(1, "reset_pc", "Program Counter at Reset", true), busError(2, "bus_err", "Bus Error"),
        addressError(3, "addr_err", "Address Error"), illegalInstruction(4, "illegal_inst", "Illegal Instruction"),
        divideByZero(5, "zero_div", "Divide By Zero"), chk(6, "chk", "CHK Instruction"),
        trapv(7, "trapv", "TRAPV instruction"), privilegeViolation(8, "priv_vio", "Privilege Violation"),
        trace(9, "trace", "Trace"), line1010(10, "line_1010", "Line 1010 Emulator"),
        line1111(11, "line_1111", "Line 1111 Emulator"),
        coprocessorProtocol(14, "copro_proto", "Coprocessor Protocol Violation"),
        formatError(15, "format_err", "Format Error"),
        uninitializedInterrupt(16, "uninit_int", "Uninitialized Interrupt"),
        spuriousInterrupt(24, "spurious_int", "Spurious Interrupt"), autoVector1(25, "autovec1", "Level 1 Autovector"),
        autoVector2(26, "autovec2", "Level 2 Autovector"), autoVector3(27, "autovec3", "Level 3 Autovector"),
        autoVector4(28, "autovec4", "Level 4 Autovector"), autoVector5(29, "autovec5", "Level 5 Autovector"),
        autoVector6(30, "autovec6", "Level 6 Autovector"), autoVector7(31, "autovec7", "Level 7 Autovector"),
        trap0(32, "trap0", "TRAP #0"), trap1(33, "trap1", "TRAP #1"), trap2(34, "trap2", "TRAP #2"),
        trap3(35, "trap3", "TRAP #3"), trap4(36, "trap4", "TRAP #4"), trap5(37, "trap5", "TRAP #5"),
        trap6(38, "trap6", "TRAP #6"), trap7(39, "trap7", "TRAP #7"), trap8(40, "trap8", "TRAP #8"),
        trap9(41, "trap9", "TRAP #9"), trap10(42, "trap10", "TRAP #10"), trap11(43, "trap11", "TRAP #11"),
        trap12(44, "trap12", "TRAP #12"), trap13(45, "trap13", "TRAP #13"), trap14(46, "trap14", "TRAP #14"),
        trap15(47, "trap15", "TRAP #15");

        public int index;
        public String name;
        public String desc;
        public boolean justAddr;

        Vector(int index, String name, String desc) {
            this.index = index;
            this.name = name;
            this.desc = desc;
        }

        Vector(int index, String name, String desc, boolean justAddr) {
            this(index, name, desc);
            this.justAddr = justAddr;
        }
    }

}