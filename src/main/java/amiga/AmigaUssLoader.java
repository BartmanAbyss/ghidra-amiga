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

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import ghidra.app.util.Option;
import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.AbstractLibrarySupportLoader;
import ghidra.app.util.opinion.LoadSpec;
import ghidra.framework.Application;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.lang.LanguageCompilerSpecPair;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.util.task.TaskMonitor;
import uss.UssFile;

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
	protected void load(ByteProvider provider, LoadSpec loadSpec, List<Option> options, Program program, TaskMonitor monitor, MessageLog log) throws IOException {
		FlatProgramAPI fpa = new FlatProgramAPI(program);
		Memory mem = program.getMemory();
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
		AmigaUtils.createCustomSegment(fpa, fdm, log);

		// TODO: vectors, ROM, CPU state, descriptions

		//AmigaUtils.analyzeResident(mem, fpa, fdm, startAddr, log);
		//AmigaUtils.setFunction(fpa, startAddr, "start", log);
	}
}
