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
package v8_bytecode;

import java.io.IOException;
import java.util.*;

import ghidra.app.util.Option;
import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.AbstractLibrarySupportLoader;
import ghidra.app.util.opinion.LoadSpec;
import ghidra.framework.options.Options;
import ghidra.program.model.lang.LanguageCompilerSpecPair;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import v8_bytecode.allocator.JscParser;
import v8_bytecode.allocator.ObjectsAllocator;

public class V8_bytecodeLoader extends AbstractLibrarySupportLoader {

	private static final long INSTANCE_SIZE = 0x3BEL;

	static final String LDR_NAME = "Jsc (Bytenode) Loader";
	
	private JscParser parser = null;
	private V8_VersionDetector verDetector = null;

	@Override
	public String getName() {
		return LDR_NAME;
	}

	@Override
	public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
		List<LoadSpec> loadSpecs = new ArrayList<>();

		BinaryReader reader = new BinaryReader(provider, true);

		long magic = reader.readNextUnsignedInt();

		if (magic == (0xC0DE0000L ^ INSTANCE_SIZE)) {
			verDetector = new V8_VersionDetector();
			
			final long versionHash = reader.readNextUnsignedInt();
			final var is32Bit = verDetector.detectBitness(versionHash);
			
			if (is32Bit) {
				loadSpecs.add(new LoadSpec(this, ObjectsAllocator.CODE_BASE, new LanguageCompilerSpecPair("V8:LE:32:default", "default"), true));
			} else {
				loadSpecs.add(new LoadSpec(this, ObjectsAllocator.CODE_BASE, new LanguageCompilerSpecPair("V8:LE:64:default", "default"), true));
			}
		}

		return loadSpecs;
	}

	@Override
	protected void load(ByteProvider provider, LoadSpec loadSpec, List<Option> options, Program program,
			TaskMonitor monitor, MessageLog log) throws CancelledException, IOException {
		
		Options aOpts = program.getOptions(Program.ANALYSIS_PROPERTIES);
		aOpts.setBoolean("Decompiler Switch Analysis", false);

		BinaryReader reader = new BinaryReader(provider, true);

		try {
			final String descr = program.getLanguage().getLanguageDescription().getVariant();
			parser = new JscParser(reader, descr.equalsIgnoreCase("x32"), program, monitor, log);
			parser.parse();
			parser.postAllocate();
		} catch (Exception e) {
			e.printStackTrace();
			log.appendException(e);
		}
	}
}
