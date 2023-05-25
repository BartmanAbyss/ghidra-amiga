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

import java.util.ArrayList;
import java.util.List;

import fd.FdFunction;
import fd.FdFunctionsInLibs;
import fd.FdLibFunctions;
import fd.FdParser;
import ghidra.app.plugin.core.analysis.ConstantPropagationContextEvaluator;
import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.Application;
import ghidra.framework.options.Options;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.ByteDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataUtilities;
import ghidra.program.model.data.FileDataTypeManager;
import ghidra.program.model.data.FunctionDefinitionDataType;
import ghidra.program.model.data.DataUtilities.ClearDataMode;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.VoidDataType;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.ReturnParameterImpl;
import ghidra.program.model.listing.VariableStorage;
import ghidra.program.model.listing.Function.FunctionUpdateType;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.program.util.SymbolicPropogator;
import ghidra.program.util.VarnodeContext;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;

public class AmigaHunkAnalyzer extends AbstractAnalyzer {
	//private static final int imageBaseOffset = 0x10000;
	private final List<String> filter = new ArrayList<String>();
	private FdFunctionsInLibs funcsList;
	
	public AmigaHunkAnalyzer() {
		super("Amiga Library Calls", "Analyses calls to system libraries", AnalyzerType.INSTRUCTION_ANALYZER);
		
		filter.add(FdParser.EXEC_LIB);
		filter.add(FdParser.DOS_LIB);
	}

	@Override
	public boolean getDefaultEnablement(Program program) {
		return program.getExecutableFormat().contains("Amiga") && !program.getExecutableFormat().contains("Kickstart");
	}

	@Override
	public boolean canAnalyze(Program program) {
		if(program.getLanguage().getProcessor().toString().equals("68000")) {
			funcsList = new FdFunctionsInLibs();
			return true;
		}
		funcsList = null;
		return false;
	}
	
	@Override
	public void registerOptions(Options options, Program program) {
		if (funcsList == null) {
			return;
		}

		String[] libsList = funcsList.getLibsList(null);
		for (String lib : libsList) {
			boolean defaultValue = filter.contains(lib);
			options.registerOption(lib, defaultValue, null, String.format("Analyze calls from %s", lib));
		}
	}
	
	@Override
	public void optionsChanged(Options options, Program program) {
		super.optionsChanged(options, program);

		if (funcsList == null) {
			return;
		}
		
		filter.clear();
		
		String[] libsList = funcsList.getLibsList(filter);
		for (String lib : libsList) {
			if (options.getBoolean(lib, false)) {
				filter.add(lib);
			}
		}
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log) {
		monitor.setMessage("Creating library functions...");
		
		FlatProgramAPI fpa = new FlatProgramAPI(program);
	
		try {
			var fdm = fpa.openDataTypeArchive(Application.getModuleDataFile("amiga_ndk39.gdt").getFile(false), true);
			for(String lib : funcsList.getLibsList(filter)) {
				createFunctionsSegment(fpa, fdm, lib, funcsList.getFunctionTableByLib(lib), log);
			}
		} catch (Exception e) {
			log.appendException(e);
			return false;
		}
		
		monitor.setMessage("Analysing library calls...");

		FunctionIterator fiter = program.getFunctionManager().getFunctions(set, true);
		while (fiter.hasNext()) {
			if (monitor.isCancelled()) {
				break;
			}

			Function func = fiter.next();
			Address start = func.getEntryPoint();
			
			SymbolicPropogator symEval = new SymbolicPropogator(program);
			symEval.setParamRefCheck(true);
			symEval.setReturnRefCheck(true);
			symEval.setStoredRefCheck(true);

			try {
				flowConstants(program, start, func.getBody(), symEval,  monitor);
			} catch (CancelledException e) {
				log.appendException(e);
				return false;
			}
		}

		return true;
	}
	
	private static DataType getAmigaDataType(String type, FileDataTypeManager fdm) {
		DataType dataType = PointerDataType.dataType;
		type = type.replace("struct ", "");
		type = type.replace("const ", "");
		type = type.replace("CONST ", "");
		type = type.replace("volatile ", "");
		type = type.replace("VOLATILE ", "");
		if(type.contains("("))
			return new PointerDataType(new FunctionDefinitionDataType("FUNC")); // TODO: correct function pointer type
		for(var word : type.split(" ")) {
			if(word.equals("*")) {
				dataType = new PointerDataType(dataType);
			} else if(word.equals("**")) {
				dataType = new PointerDataType(new PointerDataType(dataType));
			} else {
				var list = new ArrayList<DataType>();
				fdm.findDataTypes(word, list);
				dataType = !list.isEmpty() ? list.get(0) : null;
				if(dataType == null)
					System.out.println(word + " not found!");
			}
		}
		return dataType;
	}

	private static void createFunctionsSegment(FlatProgramAPI fpa, FileDataTypeManager fdm, String lib, FdLibFunctions funcs, MessageLog log) throws InvalidInputException, DuplicateNameException, CodeUnitInsertionException {
		if ((null == funcs) || (fpa.getMemoryBlock(lib) != null)) {
			return;
		}
		FdFunction[] funcArr = funcs.getFunctions();
		long segAlign = Math.max(2, 0x1000);
		long segSize = 6 * Math.max(5, 7);  // Library 5+, Device 7+
		for (FdFunction func : funcArr) {
			segSize = Math.max(segSize, Math.abs(func.getBias()) + 6);
		}
		segSize = ((segSize + (segAlign - 1)) / segAlign) * segAlign;
		Address segAddr = fpa.toAddr(AmigaHunkLoader.getImageBase(0));
		for (MemoryBlock memBlock : fpa.getMemoryBlocks()) {
			if (memBlock.contains(segAddr) || memBlock.contains(segAddr.add(segSize - 1)) || (
				(segAddr.getOffset() <= memBlock.getStart().getOffset()) &&
				(memBlock.getEnd().getOffset() <= segAddr.add(segSize - 1).getOffset()))) {
				segAddr = memBlock.getEnd().add(1);
				long segRem = segAddr.getOffset() % segAlign;
				if (segRem > 0) {
					segAddr = segAddr.add(segAlign - segRem);
				}
			}
		}
		
		AmigaUtils.createSegment(null, fpa, lib, segAddr.getOffset(), segSize, true, true, log);
		
		for (FdFunction func : funcArr) {
			Address funcAddress = segAddr.add(Math.abs(func.getBias()));
			AmigaUtils.setFunction(fpa, funcAddress, func.getName(true).replace(FdFunction.LIB_SPLITTER, "_"), log);
			Function function = fpa.getFunctionAt(funcAddress);
			function.setCustomVariableStorage(true);

			List<ParameterImpl> params = new ArrayList<>();
			Program program = fpa.getCurrentProgram();
			for (var arg : func.getArgs()) {
				var dataType = getAmigaDataType(arg.type, fdm);
				params.add(new ParameterImpl(arg.name, dataType, program.getRegister(arg.reg), program));
			}

			var retType = func.getReturnType();
			var returnValue = retType.equals("VOID") ? new ReturnParameterImpl(VoidDataType.dataType, VariableStorage.VOID_STORAGE, program) : new ReturnParameterImpl(getAmigaDataType(retType, fdm), program.getRegister("D0"), program);
			function.updateFunction(null, returnValue, FunctionUpdateType.CUSTOM_STORAGE, true, SourceType.ANALYSIS, params.toArray(ParameterImpl[]::new));
			DataUtilities.createData(program, funcAddress, new ArrayDataType(ByteDataType.dataType, 6, -1), -1, false, ClearDataMode.CLEAR_ALL_UNDEFINED_CONFLICT_DATA);
		}
	}
	
	public AddressSetView flowConstants(final Program program, Address flowStart, AddressSetView flowSet, final SymbolicPropogator symEval, final TaskMonitor monitor) throws CancelledException {
		ConstantPropagationContextEvaluator eval =
			new ConstantPropagationContextEvaluator(monitor, true) {
				@Override
				public boolean evaluateContext(VarnodeContext context, Instruction instr) {
					String mnemonic = instr.getMnemonicString();

					if (mnemonic.equals("jsr") || mnemonic.equals("jmp")) {
						Object[] objs = instr.getOpObjects(0);
						Register reg = instr.getRegister(1);
						if (reg != null && reg.getName().equals("A6") && objs.length != 0 && (objs[0] instanceof Scalar)) {
							int val = (int)((Scalar)objs[0]).getSignedValue();
							
							if (val >= 0) {
								return false;
							}
							FdFunction[] funcs = funcsList.getLibsFunctionsByBias(filter, val);
							
							for (FdFunction func : funcs) {
								MemoryBlock libMemory = program.getMemory().getBlock(func.getLib());
								if (libMemory != null) {
									Address funcStart = libMemory.getStart().add(Math.abs(func.getBias()));
									if (libMemory.contains(funcStart)) {
										Reference primaryRef = instr.getPrimaryReference(1);

										instr.addOperandReference(1, funcStart, RefType.CALL_OVERRIDE_UNCONDITIONAL, SourceType.ANALYSIS);

										if (((null == primaryRef) || (SourceType.ANALYSIS == primaryRef.getSource())) &&
												!func.isPrivate() && func.getLib().equals(FdParser.EXEC_LIB)) {
											for (Reference ref : instr.getOperandReferences(1)) {
												if (funcStart.equals(ref.getToAddress())) {
													instr.setPrimaryMemoryReference(ref);
													break;
												}
											}
										}
									}
								}
							}
						}
					}
					return false;
				}
			};

		return symEval.flowConstants(flowStart, flowSet, eval, true, monitor);
	}
}
