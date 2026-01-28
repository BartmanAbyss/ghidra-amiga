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

import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.ByteProviderInputStream;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.AbstractLibrarySupportLoader;
import ghidra.app.util.opinion.LoadSpec;
import ghidra.framework.Application;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.lang.LanguageCompilerSpecPair;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.util.task.TaskMonitor;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

public class AmigaKickstartLoader extends AbstractLibrarySupportLoader {
	@Override
	public String getName() {
		return "Amiga Kickstart ROM";
	}
	
	@Override
	public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) {
		List<LoadSpec> loadSpecs = new ArrayList<>();
		try {
			if(provider.readByte(0) == 0x11 && provider.readByte(1) == 0x11)
				loadSpecs.add(new LoadSpec(this, 0x100_0000 - provider.length(), new LanguageCompilerSpecPair("68000:BE:32:default", "default"), true));
		} catch(Exception e) {
		}

		return loadSpecs;
	}

	@Override
	protected void load(Program program, ImporterSettings importerSettings) throws IOException {
		FlatProgramAPI fpa = new FlatProgramAPI(program);
		Memory mem = program.getMemory();

		MessageLog log = importerSettings.log();
		ByteProvider provider = importerSettings.provider();
		TaskMonitor monitor = importerSettings.monitor();
		LoadSpec loadSpec = importerSettings.loadSpec();

		try {
			loadKickstart(provider, loadSpec.getDesiredImageBase(), fpa, monitor, mem, log);
		} catch (Throwable e) {
			e.printStackTrace();
			log.appendException(e);
		}
	}

	private static void loadKickstart(ByteProvider provider, long imageBase, FlatProgramAPI fpa, TaskMonitor monitor, Memory mem, MessageLog log) throws Throwable {
		var block = AmigaUtils.createSegment(new ByteProviderInputStream(provider), fpa, "ROM", imageBase, provider.length(), false, true, log);
		var startAddr = block.getStart().add(2);

		var fdm = fpa.openDataTypeArchive(Application.getModuleDataFile("amiga_ndk39.gdt").getFile(false), true);
		AmigaUtils.createCustomSegment(fpa, fdm, log);
		AmigaUtils.addTypes(fpa.getCurrentProgram(), log);
		AmigaUtils.analyzeResident(mem, fpa, fdm, startAddr, log);
		AmigaUtils.setFunction(fpa, startAddr, "start", log);
	}
}
