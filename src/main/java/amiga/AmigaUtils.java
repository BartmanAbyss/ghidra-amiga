package amiga;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;

import javax.swing.JFileChooser;
import javax.swing.filechooser.FileNameExtensionFilter;

import docking.widgets.OptionDialog;
import fd.FdFunction;
import fd.FdFunctionsInLibs;
import fd.FdLibFunctions;
import fd.FdParser;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOutOfBoundsException;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.data.DataUtilities;
import ghidra.program.model.data.DataUtilities.ClearDataMode;
import ghidra.program.model.data.FileDataTypeManager;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.WordDataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Function.FunctionUpdateType;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;
import structs.CopperInst;
import structs.InitData_Type;
import structs.InitTable;

public class AmigaUtils {
	static final byte[] RTC_MATCHWORD = new byte[] { 0x4A, (byte) 0xFC };
	static final byte RTF_AUTOINIT = (byte) (1 << 7);

	public static DataType getAmigaDataType(FileDataTypeManager fdm, String type) {
		var list = new ArrayList<DataType>();
		fdm.findDataTypes(type, list);
		return !list.isEmpty() ? list.get(0) : null;
	}

	public static MemoryBlock createSegment(InputStream stream, FlatProgramAPI fpa, String name, long address, long size, boolean write, boolean execute, MessageLog log) {
		MemoryBlock block;
		try {
			Program program = fpa.getCurrentProgram();
			
			int transId = program.startTransaction(String.format("Create %s block", name));
			block = fpa.createMemoryBlock(name, fpa.toAddr(address), stream, size, false);
			program.endTransaction(transId, true);
			
			block.setRead(true);
			block.setWrite(write);
			block.setExecute(execute);
			return block;
		} catch (Exception e) {
			log.appendException(e);
			return null;
		}
	}

	public static void createExecBaseSegment(FlatProgramAPI fpa, FileDataTypeManager fdm, MessageLog log) {
		MemoryBlock exec = createSegment(null, fpa, "EXEC", 0x4, 4, false, false, log);
		
		Program program = fpa.getCurrentProgram();

		try {
			DataUtilities.createData(program, exec.getStart(), new PointerDataType(getAmigaDataType(fdm, "ExecBase")), -1, false, ClearDataMode.CLEAR_ALL_UNDEFINED_CONFLICT_DATA);
		} catch (CodeUnitInsertionException e) {
			log.appendException(e);
		}
	}

	public static void createCustomSegment(FlatProgramAPI fpa, FileDataTypeManager fdm, MessageLog log) {
		// TODO: CIA
		log.appendMsg("Creating custom chips memory block");
		var block = createSegment(null, fpa, "Custom", 0xdff000, 0x200, true, false, log);
		var program = fpa.getCurrentProgram();
		try {
			var regs = AmigaUtils.getAmigaDataType(fdm, "Custom");
			DataUtilities.createData(program, block.getStart(), regs, -1, false, ClearDataMode.CLEAR_ALL_UNDEFINED_CONFLICT_DATA);
			fpa.createLabel(block.getStart(), "Custom", false);
		} catch (Exception e) {
			log.appendException(e);
		}
	}

	public static void addTypes(Program program, MessageLog log) {
		program.getDataTypeManager().addDataType(CopperInst.dataType, DataTypeConflictHandler.DEFAULT_HANDLER);
	}

	private static String showSelectFile(String title) {
		JFileChooser jfc = new JFileChooser(new File("."));
		jfc.setDialogTitle(title);

		jfc.setFileFilter(new FileNameExtensionFilter("Functions Definition File", "sfd"));
		jfc.setMultiSelectionEnabled(false);

		if (jfc.showOpenDialog(null) == JFileChooser.APPROVE_OPTION) {
			return jfc.getSelectedFile().getAbsolutePath();
		}

		return null;
	}

	public static void analyzeResident(Memory mem, FlatProgramAPI fpa, FileDataTypeManager fdm, Address startAddr, MessageLog log) {
		Program program = fpa.getCurrentProgram();
		ReferenceManager refMgr = program.getReferenceManager();
		var funcsList = new FdFunctionsInLibs();

		try {
			while (true) {
				Address addr = fpa.find(startAddr, RTC_MATCHWORD);

				if (addr == null) {
					break;
				}

				long rt_MatchTag = mem.getInt(addr.add(2));

				startAddr = addr.add(2);
				if (addr.getOffset() != rt_MatchTag) {
					continue;
				}

				DataUtilities.createData(program, addr, AmigaUtils.getAmigaDataType(fdm, "Resident"), -1, false, ClearDataMode.CLEAR_ALL_UNDEFINED_CONFLICT_DATA);
				byte rt_Flags = mem.getByte(addr.add(10));

				var NameAddr = addr.getNewAddress(mem.getInt(addr.add(14), true));
				var builder = new StringBuilder();
				for(int i = 0; mem.getByte(NameAddr.add(i)) != 0 && mem.getByte(NameAddr.add(i)) != 0xd && mem.getByte(NameAddr.add(i)) != 0xa; i++)
					builder.append(Character.toChars(mem.getByte(NameAddr.add(i))));
				var rt_Name = builder.toString();

				if ((rt_Flags & RTF_AUTOINIT) == RTF_AUTOINIT) {
					long rt_Init = mem.getInt(addr.add(22));
					Address rt_InitAddr = fpa.toAddr(rt_Init);

					DataUtilities.createData(program, rt_InitAddr, (new InitTable()).toDataType(), -1, false, ClearDataMode.CLEAR_ALL_UNDEFINED_CONFLICT_DATA);

					/* long it_DataSize = */mem.getInt(rt_InitAddr.add(0));
					long it_FuncTable = mem.getInt(rt_InitAddr.add(4));
					long it_DataInit = mem.getInt(rt_InitAddr.add(8));
					long it_InitFunc = mem.getInt(rt_InitAddr.add(12));

					Address it_InitFuncAddr = fpa.toAddr(it_InitFunc);
					setFunction(fpa, it_InitFuncAddr, String.format("it_InitFunc_%06X", addr.getOffset()), log);
					Function func = fpa.getFunctionAt(it_InitFuncAddr);
					func.setCustomVariableStorage(true);

					List<ParameterImpl> params = new ArrayList<>();
					
					Structure baseStruct = new StructureDataType("BaseLib", 0);
					baseStruct.add(AmigaUtils.getAmigaDataType(fdm, "Library"), "base", null);
					baseStruct.add(WordDataType.dataType, "field0", null);

					params.add(new ParameterImpl("libBase", PointerDataType.dataType, program.getRegister("A6"), program));
					params.add(new ParameterImpl("seglist", PointerDataType.dataType, program.getRegister("A0"), program));
					params.add(new ParameterImpl("lib", new PointerDataType(baseStruct), program.getRegister("D0"), program));

					func.updateFunction(null, null, FunctionUpdateType.CUSTOM_STORAGE, true, SourceType.ANALYSIS, params.toArray(ParameterImpl[]::new));

					if (it_DataInit != 0) {
						Address it_DataInitAddr = fpa.toAddr(it_DataInit);
						program.getSymbolTable().createLabel(it_DataInitAddr, String.format("it_DataInit_%06X", addr.getOffset()), SourceType.ANALYSIS);

						while (true) {
							InitData_Type tt;
							try {
								tt = new InitData_Type(mem, fpa, it_DataInitAddr.getOffset());
							} catch (Exception e) {
								break;
							}
							DataUtilities.createData(program, it_DataInitAddr, tt.toDataType(), -1, false, ClearDataMode.CLEAR_ALL_UNDEFINED_CONFLICT_DATA);
							it_DataInitAddr = it_DataInitAddr.add(tt.toDataType().getLength());
						}
					}
					Address it_FuncTableAddr = fpa.toAddr(it_FuncTable);
					program.getSymbolTable().createLabel(it_FuncTableAddr, String.format("it_FuncTable_%06X", addr.getOffset()), SourceType.ANALYSIS);

					int i = 0;
					boolean askedForFd = false;
					FdLibFunctions funcTable = null;
					
					boolean isRelative = (mem.getShort(it_FuncTableAddr) & 0xFFFF) == 0xFFFF;

					while (true) {
						long funcAddr;
						
						if (isRelative) {
							short relVal = mem.getShort(it_FuncTableAddr.add((i + 1) * 2));
							
							if ((relVal & 0xFFFF) == 0xFFFF) {
								break;
							}
							
							funcAddr = it_FuncTableAddr.add(relVal).getOffset();
						} else {
							funcAddr = mem.getInt(it_FuncTableAddr.add(i * 4));
						}
						
						Address funcAddr_ = fpa.toAddr(funcAddr);
						if (!mem.contains(funcAddr_)) {
							break;
						}

						var libName = rt_Name.replace('.', '_');;
						if(funcsList.findLibIndex(libName) != -1)
							funcTable = funcsList.getFunctionTableByLib(libName);

						if(funcTable == null && !askedForFd && i >= 4) {
							TimeUnit.SECONDS.sleep(1);
							if (OptionDialog.YES_OPTION == OptionDialog.showYesNoDialogWithNoAsDefaultButton(null,
									"Question", String.format("Do you have %s.sfd file for this library?", rt_Name))) {
								String fdPath = showSelectFile("Select file...");
								funcTable = FdParser.readSfdFile(fdPath);
							}
							askedForFd = true;
						}

						if (isRelative) {
							DataUtilities.createData(program, it_FuncTableAddr.add((i + 1) * 2), WordDataType.dataType, -1,
									false, ClearDataMode.CLEAR_ALL_UNDEFINED_CONFLICT_DATA);
							refMgr.addMemoryReference(it_FuncTableAddr.add((i + 1) * 2), funcAddr_, RefType.DATA, SourceType.ANALYSIS, 0);
						} else {
							DataUtilities.createData(program, it_FuncTableAddr.add(i * 4), PointerDataType.dataType, -1,
									false, ClearDataMode.CLEAR_ALL_UNDEFINED_CONFLICT_DATA);
						}

						FdFunction funcDef = null;
						if (funcTable != null) {
							funcDef = funcTable.getFunctionByIndex(i - 4);
						}

						String name;

						switch (i) {
						case 0:
							name = "LIB_OPEN";
							break;
						case 1:
							name = "LIB_CLOSE";
							break;
						case 2:
							name = "LIB_EXPUNGE";
							break;
						case 3:
							name = "LIB_EXTFUNC";
							break;
						default:
							name = funcDef != null ? funcDef.getName(false) : String.format("LibFunc_%03d", i - 4);
						}

						setFunction(fpa, funcAddr_, name, log);
						func = fpa.getFunctionAt(funcAddr_);
						func.setCustomVariableStorage(true);

						params = new ArrayList<>();

						params.add(new ParameterImpl("base", new PointerDataType(baseStruct), program.getRegister("A6"), program));

						if (funcDef != null) {
							for (var arg : funcDef.getArgs()) {
								params.add(new ParameterImpl(arg.name, PointerDataType.dataType, program.getRegister(arg.reg), program));
							}
						}

						func.updateFunction(null, null, FunctionUpdateType.CUSTOM_STORAGE, true,
								SourceType.ANALYSIS, params.toArray(ParameterImpl[]::new));
						i++;
					}
				} // autoinit
			}
		} catch (InvalidInputException | MemoryAccessException | AddressOutOfBoundsException | CodeUnitInsertionException | DuplicateNameException | IOException | InterruptedException e) {
			log.appendException(e);
		}
	}

	public static void setFunction(FlatProgramAPI fpa, Address address, String name, MessageLog log) {
		try {
			fpa.disassemble(address);
			fpa.createFunction(address, name);
			fpa.addEntryPoint(address);
			fpa.getCurrentProgram().getSymbolTable().createLabel(address, name, SourceType.IMPORTED);
		} catch (InvalidInputException e) {
			log.appendException(e);
		}
	}
}