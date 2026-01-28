/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package amiga;

import ghidra.app.plugin.core.reloc.InstructionStasher;
import ghidra.app.util.Option;
import ghidra.app.util.OptionException;
import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.AbstractLibrarySupportLoader;
import ghidra.app.util.opinion.LoadSpec;
import ghidra.app.util.opinion.Loader;
import ghidra.framework.Application;
import ghidra.framework.model.DomainObject;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DWordDataType;
import ghidra.program.model.data.DataUtilities;
import ghidra.program.model.data.DataUtilities.ClearDataMode;
import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.LanguageCompilerSpecPair;
import ghidra.program.model.lang.LanguageNotFoundException;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.util.task.TaskMonitor;
import hunk.*;

import java.io.ByteArrayInputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

public class AmigaHunkLoader extends AbstractLibrarySupportLoader {
	public static final int DEF_IMAGE_BASE = 0x21F000;

	static final String OPTION_NAME = "ImageBase";
	public static Address imageBase = null;

	static final String defsSegmName = "DEFS";
	static final String refsSegmName = "REFS";
	static final int defsSegmImageBaseOffset = 0x10000;
	static int refsLastIndex = 0;
	static int defsLastIndex = 0;

	@Override
	public String getName() {
		return "Amiga Hunk Executable";
	}
	
	public static int getImageBase(int offset) {
		return (int) (((imageBase != null) ? imageBase.getOffset() : DEF_IMAGE_BASE) + offset);
	}

	@Override
	public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) {
		List<LoadSpec> loadSpecs = new ArrayList<>();
		try {
			if(HunkBlockFile.isHunkBlockFile(new BinaryReader(provider, false)))
				loadSpecs.add(new LoadSpec(this, 0, new LanguageCompilerSpecPair("68000:BE:32:default", "default"), true));
		} catch(Exception e) {
		}

		return loadSpecs;
	}

	@Override
	protected void load(Program program, ImporterSettings importerSettings)  {
		refsLastIndex = 0;
		defsLastIndex = 0;
		
		FlatProgramAPI fpa = new FlatProgramAPI(program);
		Memory mem = program.getMemory();

		MessageLog log = importerSettings.log();
		ByteProvider provider = importerSettings.provider();
		TaskMonitor monitor = importerSettings.monitor();

		BinaryReader reader = new BinaryReader(provider, false);

		// executable
		HunkBlockType type = HunkBlockFile.peekType(reader);
        HunkBlockFile hbf = null;
        try {
            hbf = new HunkBlockFile(reader, type == HunkBlockType.TYPE_LOADSEG);
        } catch (HunkParseError e) {
 			e.printStackTrace();
			log.appendException(e);
        }
        switch (type) {
		case TYPE_LOADSEG: 
		case TYPE_UNIT:
			try {
				loadExecutable(imageBase, type == HunkBlockType.TYPE_LOADSEG, hbf, fpa, monitor, mem, log);
			} catch (Throwable e) {
				e.printStackTrace();
				log.appendException(e);
			}
		break;
		case TYPE_LIB:
		break;
		default:
		break;
		}
	}

	private static void loadExecutable(Address imageBase, boolean isExecutable, HunkBlockFile hbf, FlatProgramAPI fpa, TaskMonitor monitor, Memory mem, MessageLog log) throws Throwable {
		BinImage bi = BinFmtHunk.loadImage(hbf, log);
		
		if (bi == null) {
			return;
		}
		
		int _imageBase = getImageBase(0);

		Relocate rel = new Relocate(bi);
		int[] addrs = rel.getSeqAddresses(_imageBase);
		List<byte[]> datas;
		try {
			datas = rel.relocate(addrs);
		} catch (HunkParseError e1) {
			log.appendException(e1);
			return;
		}
		
		int lastSectAddress = 0;

		for (Segment seg : bi.getSegments()) {
			int segOffset = addrs[seg.getId()];
			int size = seg.getSize();
			
			if (segOffset + size > lastSectAddress) {
				lastSectAddress = segOffset + size;
			}

			ByteArrayInputStream segBytes = new ByteArrayInputStream(datas.get(seg.getId()));

			if (segBytes.available() == 0) {
				continue;
			}

			boolean exec = seg.getType() == SegmentType.SEGMENT_TYPE_CODE;
			boolean write = seg.getType() == SegmentType.SEGMENT_TYPE_DATA;

			AmigaUtils.createSegment(segBytes, fpa, seg.getName(), segOffset, size, write, exec, log);
			relocateSegment(seg, segOffset, datas, mem, fpa, log);
		}
		
		for (Segment seg : bi.getSegments()) {
			int segOffset = addrs[seg.getId()];

			applySegmentDefs(seg, segOffset, fpa, fpa.getCurrentProgram().getSymbolTable(), log, lastSectAddress);
		}
		
		Address startAddr = fpa.toAddr(addrs[0]);
		
		var fdm = fpa.openDataTypeArchive(Application.getModuleDataFile("amiga_ndk39.gdt").getFile(false), true);
		AmigaUtils.createExecBaseSegment(fpa, fdm, log);
		AmigaUtils.createCustomSegment(fpa, fdm, log);
		AmigaUtils.addTypes(fpa.getCurrentProgram(), log);
		AmigaUtils.analyzeResident(mem, fpa, fdm, startAddr, log);
		
		if(isExecutable)
			AmigaUtils.setFunction(fpa, startAddr, "start", log);
		
		addSymbols(bi.getSegments(), fpa.getCurrentProgram().getSymbolTable(), addrs, fpa);
	}

	private static void addSymbols(Segment segs[], SymbolTable st, int addrs[], FlatProgramAPI fpa) throws Throwable {
		for (Segment seg : segs) {
			hunk.Symbol[] symbols = seg.getSymbols(seg);
			if(symbols.length > 0) {
				for(hunk.Symbol symbol : symbols) {
					String name = symbol.getName();
					int offset = symbol.getOffset();
					st.createLabel(fpa.toAddr(addrs[seg.getId()]+offset), name, SourceType.IMPORTED);
				}
			}
		}
	}

	private static void relocateSegment(Segment seg, int segOffset, final List<byte[]> datas, Memory mem, FlatProgramAPI fpa, MessageLog log) {
		Segment[] toSegs = seg.getRelocationsToSegments();

		for (Segment toSeg : toSegs) {
			Reloc[] reloc = seg.getRelocations(toSeg);

			for (Reloc r : reloc) {
				int dataOffset = r.getOffset();

				ByteBuffer buf = ByteBuffer.wrap(datas.get(seg.getId()));
				int newAddr = 0;
				
				try {
					switch (r.getWidth()) {
					case 4:
						newAddr = buf.getInt(dataOffset) + r.getAddend();
						break;
					case 2:
						newAddr = buf.getShort(dataOffset) + r.getAddend();
						break;
					case 1:
						newAddr = buf.get(dataOffset) + r.getAddend();
						break;
					}
					patchReference(mem, fpa.toAddr(segOffset + dataOffset), newAddr, r.getWidth());
				} catch (MemoryAccessException | CodeUnitInsertionException e) {
					log.appendException(e);
					return;
				}
			}
		}
	}
	
	private static void applySegmentDefs(Segment seg, int segOffset, FlatProgramAPI fpa, SymbolTable st, MessageLog log, int lastSectAddress) throws Throwable {
		if (seg.getSegmentInfo().getDefinitions() == null) {
			return;
		}
		
		Memory mem = fpa.getCurrentProgram().getMemory();
		
		for (final XDefinition entry : seg.getSegmentInfo().getDefinitions()) {
			Address defAddr = fpa.toAddr(entry.getOffset());
			
			if (!entry.isAbsolute()) {
				defAddr = fpa.toAddr(segOffset + entry.getOffset());
			}
			
			if (mem.contains(defAddr)) {
				st.createLabel(defAddr, entry.getName(), SourceType.USER_DEFINED);
				
				if (entry.getName().equals("___startup")) {
					AmigaUtils.setFunction(fpa, defAddr, entry.getName(), log);
				}
			} else {
				addDefinition(mem, fpa, st, entry.getName(), entry.getOffset());
			}
		}
		
		if (seg.getSegmentInfo().getReferences() == null) {
			return;
		}
		
		for (final XReference entry : seg.getSegmentInfo().getReferences()) {
			for (Integer offset : entry.getOffsets()) {
				Address fromAddr = fpa.toAddr(segOffset + offset);
				int newAddr = 0;
				
				switch (entry.getType()) {
				case R_ABS: {
					newAddr = addReference(mem, fpa, st, entry.getName(), lastSectAddress);
					patchReference(mem, fromAddr, newAddr, entry.getWidth());
				} break;
				case R_SD: {
					newAddr = addReference(mem, fpa, st, entry.getName(), lastSectAddress);
					patchReference(mem, fromAddr, (int) (newAddr - lastSectAddress), entry.getWidth());
				} break;
				case R_PC: {
					newAddr = addReference(mem, fpa, st, entry.getName(), lastSectAddress);
					patchReference(mem, fromAddr, (int) (newAddr - fromAddr.getOffset()), entry.getWidth());
				} break;
				}
				
			}
		}
	}
	
	private static void patchReference(Memory mem, Address fromAddr, int toAddr, int width) throws MemoryAccessException, CodeUnitInsertionException {
		InstructionStasher instructionStasher = new InstructionStasher(mem.getProgram(), fromAddr);
		switch (width) {
		case 4:
			mem.setBytes(fromAddr, intToBytes(toAddr));
			break;
		case 2:
			mem.setBytes(fromAddr, shortToBytes((short) toAddr));
			break;
		case 1:
			mem.setBytes(fromAddr, new byte[] {(byte) toAddr});
			break;
		}
		instructionStasher.restore();
	}

	private static int addReference(Memory mem, FlatProgramAPI fpa, SymbolTable st, String name, int lastSectAddress) throws Throwable {
		List<Symbol> syms = st.getGlobalSymbols(name);
		
		if (syms.size() > 0) {
			return (int) syms.get(0).getAddress().getOffset();
		}
		
		MemoryBlock block = mem.getBlock(refsSegmName);
		
		if (block == null) {
			int transId = mem.getProgram().startTransaction(String.format("Create %s block", refsSegmName));
			block = mem.createUninitializedBlock(refsSegmName, fpa.toAddr(lastSectAddress), 4, false);
			mem.getProgram().endTransaction(transId, true);
		}
		
		Address newAddress = block.getStart().add(refsLastIndex * 4);
		expandBlockByDword(mem, block, newAddress, false);
		
		st.createLabel(newAddress, name, SourceType.IMPORTED);
		refsLastIndex++;
		
		return (int) newAddress.getOffset();
	}
	
	private static int addDefinition(Memory mem, FlatProgramAPI fpa, SymbolTable st, String name, int value) throws Throwable {
		List<Symbol> syms = st.getGlobalSymbols(name);
		
		if (syms.size() > 0) {
			return (int) syms.get(0).getAddress().getOffset();
		}
		
		MemoryBlock block = mem.getBlock(defsSegmName);

		if (block == null) {
			int transId = mem.getProgram().startTransaction(String.format("Create %s block", defsSegmName));
			block = mem.createInitializedBlock(defsSegmName, fpa.toAddr(getImageBase(defsSegmImageBaseOffset)), 4, (byte) 0x00, TaskMonitor.DUMMY, false);
			mem.getProgram().endTransaction(transId, true);
		}
		
		Address newAddress = block.getStart().add(defsLastIndex * 4);
		expandBlockByDword(mem, block, newAddress, true);
		
		st.createLabel(newAddress, name, SourceType.USER_DEFINED);
		mem.setInt(newAddress, value);
		DataUtilities.createData(mem.getProgram(), newAddress, DWordDataType.dataType, -1, true, ClearDataMode.CLEAR_ALL_UNDEFINED_CONFLICT_DATA);
		defsLastIndex++;
		
		return (int) newAddress.getOffset();
	}
	
	private static void expandBlockByDword(Memory mem, MemoryBlock block, Address appendAddress, boolean initialized) throws Throwable {
		if (block.getStart().equals(appendAddress)) {
			return;
		}
		
		int transId = mem.getProgram().startTransaction(String.format("Expand %s block", block.getName()));
		MemoryBlock tmp = mem.createUninitializedBlock(block.getName() + ".exp", appendAddress, 4, false);
		mem.getProgram().endTransaction(transId, true);
		
		if (initialized) {
			tmp = mem.convertToInitialized(tmp, (byte)0x00);
		}
		
		mem.join(block, tmp);
	}

	private static byte[] intToBytes(int x) {
		ByteBuffer buffer = ByteBuffer.allocate(Integer.BYTES);
		buffer.order(ByteOrder.BIG_ENDIAN);
		buffer.putInt(x);
		return buffer.array();
	}
	
	private static byte[] shortToBytes(short x) {
		ByteBuffer buffer = ByteBuffer.allocate(Short.BYTES);
		buffer.order(ByteOrder.BIG_ENDIAN);
		buffer.putShort(x);
		return buffer.array();
	}

	@Override
	public List<Option> getDefaultOptions(ByteProvider provider, LoadSpec loadSpec, DomainObject domainObject, boolean loadIntoProgram, boolean mirrorFsLayout) {
		List<Option> list = new ArrayList<Option>();

		LanguageCompilerSpecPair pair = loadSpec.getLanguageCompilerSpec();
		try {
			Language importerLanguage = getLanguageService().getLanguage(pair.languageID);
			imageBase = importerLanguage.getAddressFactory().getDefaultAddressSpace().getAddress(DEF_IMAGE_BASE);
			list.add(new Option(OPTION_NAME, imageBase, Address.class, Loader.COMMAND_LINE_ARG_PREFIX + "-baseAddr"));
		} catch (LanguageNotFoundException e) {

		}

		return list;
	}

	@Override
	public String validateOptions(ByteProvider provider, LoadSpec loadSpec, List<Option> options, Program program) {
		imageBase = null;

		for (Option option : options) {
			String optName = option.getName();
			try {
				if (optName.equals(OPTION_NAME)) {
					imageBase = (Address) option.getValue();

					long val = imageBase.getOffset();
					if (val >= 0x1000L && val <= 0x700000L) {
						break;
					}
				}
			} catch (Exception e) {
				if (e instanceof OptionException) {
					return e.getMessage();
				}
				return "Invalid value for " + optName + " - " + option.getValue();
			}
		}
		if (imageBase == null || (imageBase.getOffset() < 0x1000L) || (imageBase.getOffset() >= 0x80000000L)) {
			return "Invalid image base";
		}

		return null;
	}
}
