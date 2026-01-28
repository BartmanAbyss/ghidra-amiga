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

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.AbstractLibrarySupportLoader;
import ghidra.app.util.opinion.LoadSpec;
import ghidra.framework.Application;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.data.DataUtilities;
import ghidra.program.model.data.DataUtilities.ClearDataMode;
import ghidra.program.model.lang.LanguageCompilerSpecPair;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;
import structs.M68KVectors;
import uss.UssFile;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

public class AmigaUssLoader extends AbstractLibrarySupportLoader {
	@Override
	public String getName() {
		return "Amiga WinUAE State File (USS)";
	}
	
	@Override
	public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) {
		List<LoadSpec> loadSpecs = new ArrayList<>();
		try {
			if (UssFile.isUssFile(new BinaryReader(provider, false)))
				loadSpecs.add(new LoadSpec(this, 0, new LanguageCompilerSpecPair("68000:BE:32:default", "default"), true));
		} catch(Exception e) {
		}
		return loadSpecs;
	}

	@Override
	protected void load(Program program, ImporterSettings importerSettings) throws IOException{
		FlatProgramAPI fpa = new FlatProgramAPI(program);
		Memory mem = program.getMemory();

		MessageLog log = importerSettings.log();
		ByteProvider provider = importerSettings.provider();
		TaskMonitor monitor = importerSettings.monitor();

		try {
			loadUss(provider, fpa, monitor, mem, log);
		} catch (Throwable e) {
			e.printStackTrace();
			log.appendException(e);
		}
	}

	private static void loadUss(ByteProvider provider, FlatProgramAPI fpa, TaskMonitor monitor, Memory mem, MessageLog log) throws Throwable {
		var uss = new UssFile(new BinaryReader(provider, false), monitor, log);
		for(var m : uss.memBlocks) {
			var block = AmigaUtils.createSegment(m.content != null ? new ByteArrayInputStream(m.content) : null, fpa, m.name, m.start, m.length, true, true, log);
		}

		var fdm = fpa.openDataTypeArchive(Application.getModuleDataFile("amiga_ndk39.gdt").getFile(false), true);

		DataUtilities.createData(fpa.getCurrentProgram(), fpa.toAddr(0xdff000), AmigaUtils.getAmigaDataType(fdm, "Custom"), -1, false, ClearDataMode.CLEAR_ALL_UNDEFINED_CONFLICT_DATA);
		fpa.createLabel(fpa.toAddr(0xdff000), "Custom", false);

		AmigaUtils.addTypes(fpa.getCurrentProgram(), log);
		try {
			DataType exceptionTable = fpa.getCurrentProgram().getDataTypeManager().addDataType(new M68KVectors().toDataType(), DataTypeConflictHandler.DEFAULT_HANDLER);
			DataUtilities.createData(fpa.getCurrentProgram(), fpa.toAddr(0), exceptionTable, -1, false, ClearDataMode.CLEAR_ALL_UNDEFINED_CONFLICT_DATA);
			fpa.createLabel(fpa.toAddr(0), "ExceptionVectors", false);
		} catch (Exception e) {
			log.appendException(e);
		}

		// set PC
		var pcAddr = fpa.toAddr(uss.registers[15]);
		try {
			fpa.disassemble(pcAddr);
			fpa.addEntryPoint(pcAddr);
			fpa.getCurrentProgram().getSymbolTable().createLabel(pcAddr, "pc", SourceType.IMPORTED);
		} catch (InvalidInputException e) {
			log.appendException(e);
		}

		// TODO: CIA, ROM, CPU state, descriptions

		//AmigaUtils.analyzeResident(mem, fpa, fdm, startAddr, log);
		//AmigaUtils.setFunction(fpa, startAddr, "start", log);
	}
}
