//Disassembles a copper list at the current address
//@author Bartman/Abyss
//@category Amiga
//@keybinding
//@menupath
//@toolbar

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Register;
import ghidra.program.model.lang.RegisterValue;
import ghidra.program.model.listing.ContextChangeException;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.ProgramContext;

public class CopperList extends GhidraScript {
	@Override
	protected void run() throws Exception {
		var addr = currentAddress;
		boolean foundCopperEnd = false;
		for(int i = 0; i < 512; i++) {
			var word0 = currentProgram.getMemory().getShort(addr.add(i * 4 + 0), true);
			var word1 = currentProgram.getMemory().getShort(addr.add(i * 4 + 2), true);
			if(word0 == (short)0xffff && word1 == (short)0xfffe) {
				foundCopperEnd = true;
				break;
			}
		}
		if(!foundCopperEnd) {
			this.popup("Could not find a copper end instruction ($FFFF_FFFE) within 512 instructions of the current address.");
			return;
		}

		var types = this.getDataTypes("CopperInst");
		if(types.length > 0) {
			for(int i = 0; i < 512; i++) {
				clearListing(addr.add(i * 4), addr.add(i * 4 + 3));
				createData(addr.add(i * 4), types[0]);
				var word0 = currentProgram.getMemory().getShort(addr.add(i * 4 + 0), true);
				var word1 = currentProgram.getMemory().getShort(addr.add(i * 4 + 2), true);
				if(word0 == (short)0xffff && word1 == (short)0xfffe)
					break;
			}
		} else {
			this.popup("Can't find CopperInst data type. Program not loaded as Amiga file?");
			return;
		}
	}
}
