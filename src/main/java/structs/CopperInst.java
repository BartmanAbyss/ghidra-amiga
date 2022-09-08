package structs;

import ghidra.docking.settings.Settings;
import ghidra.program.model.data.AbstractIntegerDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.mem.MemBuffer;
import ghidra.program.model.mem.MemoryAccessException;
import structs.CustomChipRegisters.Register;

public class CopperInst extends AbstractIntegerDataType {
    public static CopperInst dataType = new CopperInst();

    public CopperInst() {
        this(null);
    }

    public CopperInst(DataTypeManager dtm) {
        super("CopperInst", false, dtm);
    }

    @Override
    public String getName() {
        return "CopperInst";
    }

    @Override
    public String getDescription() {
        return "Amiga Copper Instruction (two words)";
    }

    @Override
    public String getRepresentation(MemBuffer buf, Settings settings, int length) {
        if (length != 4) {
            // Something odd is going on...
            return super.getRepresentation(buf, settings, length);
        }

        int firstWord = 0;
        int secondWord = 0;
        try {
            firstWord = buf.getUnsignedShort(0);
            secondWord = buf.getUnsignedShort(2);
        } catch (MemoryAccessException e) {
            return super.getRepresentation(buf, settings, length);
        }

        if ((firstWord & 0x1) == 0) {
            // MOVE instruction
            int regIdx = (firstWord >> 1) & 0b11111111;
            Register reg = CustomChipRegisters.registerByIndex[regIdx];
            String name = null;
            if (reg.pair()) {
                boolean high = (regIdx % 2) == 0;
                name = high ? reg.name() + "H" : reg.name() + "L";
            } else {
                name = reg.name();
            }

            return String.format("MOVE 0x%04x,%s", secondWord, name);
        } else {
            // Either WAIT or SKIP
            String instName = ((secondWord & 0x1) == 0) ? "WAIT" : "SKIP";

            int hp = (firstWord & 0b1111111) << 1;
            int vp = firstWord >> 8;
            int he = ((firstWord & 0b1111111) << 1) | 0b11;
            int ve = ((firstWord >> 8) & 0b1111111) | 0b10000000;
            boolean bfd = (secondWord >> 15) != 0;

            if (he == 0b111111111 && ve == 0b11111111) {
                // No bits are masked out, so we'll use a simple decimal
                // presentation that is easy to construct.
                if (bfd) {
                    return String.format("%s (%d,%d)", instName, hp, vp);
                } else {
                    return String.format("%s (%d,%d)+BF", instName, hp, vp);
                }
            } else {
                // When masking is enabled our formatting is a bit more
                // involved because we want to show which bits are significant
                // and which are "don't care", and so we'll use binary.
                StringBuilder b = new StringBuilder(32);
                b.append(instName);
                b.append(" (0b");
                for (int i = 8; i >= 0; i--) {
                    boolean set = ((hp >> i) & 0b1) != 0;
                    boolean ena = ((he >> i) & 0b1) != 0;
                    if (ena) {
                        b.append(set ? '1' : '0');
                    } else {
                        b.append('X');
                    }
                }
                b.append(",0b");
                for (int i = 7; i >= 0; i--) {
                    boolean set = ((vp >> i) & 0b1) != 0;
                    boolean ena = ((ve >> i) & 0b1) != 0;
                    if (ena) {
                        b.append(set ? '1' : '0');
                    } else {
                        b.append('X');
                    }
                }
                b.append(")");
                if (bfd) {
                    b.append("+BF");
                }
                return b.toString();
            }

        }
    }

    @Override
    public DataType clone(DataTypeManager dtm) {
        return new CopperInst(dtm);
    }

    @Override
    public int getLength() {
        return 4;
    }

    @Override
    public AbstractIntegerDataType getOppositeSignednessDataType() {
        return CopperInst.dataType;
    }
}
