package v8_bytecode.allocator;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.SortedMap;
import java.util.TreeMap;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.Application;
import ghidra.framework.store.LockException;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.Enum;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlockException;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.exception.NotFoundException;
import ghidra.util.task.TaskMonitor;
import v8_bytecode.AllocHow;
import v8_bytecode.AllocPoint;
import v8_bytecode.AllocSpace;
import v8_bytecode.AllocWhere;
import v8_bytecode.CaseState;
import v8_bytecode.EnumsStorage;
import v8_bytecode.ReservObject;
import v8_bytecode.RootObject;
import v8_bytecode.RuntimeFuncArg;
import v8_bytecode.enums.AllocationAlignment;
import v8_bytecode.enums.BuiltinsEnum;
import v8_bytecode.enums.CatchPrediction;
import v8_bytecode.enums.EnumDataTypes;
import v8_bytecode.enums.RuntimesEnum;
import v8_bytecode.enums.IntrinsicsEnum;
import v8_bytecode.enums.JsRuntimesEnum;
import v8_bytecode.enums.RootsEnum;
import v8_bytecode.enums.ScriptSourceEnum;
import v8_bytecode.enums.ScriptTypeEnum;
import v8_bytecode.enums.SourcePositionTypeEnum;
import v8_bytecode.enums.TypeOfEnum;
import v8_bytecode.storage.RootsStore;
import v8_bytecode.storage.RuntimesIntrinsicsStore;
import v8_bytecode.structs.ArrayStruct;
import v8_bytecode.structs.HandlerTableItemStruct;
import v8_bytecode.structs.HandlerTableStruct;
import v8_bytecode.structs.SharedFunctionInfoStruct;

public final class JscParser {
	private List<Object> attached = new ArrayList<>();
	private List<String> builtins = new ArrayList<>();
	private List<RootObject> roots = new ArrayList<>();

	private AllocationAlignment nextAlignment = AllocationAlignment.kWordAligned; 
	private long lastHotIndex = 0L;
	private Map<AllocSpace, Integer> lastChunkIndex = new HashMap<>();
	private SortedMap<Long, Object> hots = new TreeMap<>();

	private SortedMap<AllocSpace, List<ReservObject>> reserv = new TreeMap<>();
	private List<Long> codeStubs = new ArrayList<>();
	
	private final BinaryReader reader;
	private final ObjectsAllocator allocator;
	private final Program program;
	private final DataTypeManager mgr;
	private final MessageLog log;
	private final TaskMonitor monitor;
	private static boolean is32Bit;
	
	private final int kPointerSizeLog2;
	public final int kPointerSize;
	
	private final long kPointerAlignment;
	private final long kPointerAlignmentMask;
	private final int kObjectAlignmentBits;
	
	public JscParser(BinaryReader reader, boolean is32Bit, Program program, TaskMonitor monitor, MessageLog log) throws Exception {
		this.reader = reader;
		this.program = program;
		this.mgr = program.getDataTypeManager();
		this.log = log;
		this.monitor = monitor;
		JscParser.is32Bit = is32Bit;
		
		kPointerSizeLog2 = is32Bit ? 2 : 3;
		kPointerSize = is32Bit ? 4 : 8;
		
		kPointerAlignment = (1 << kPointerSizeLog2);
		kPointerAlignmentMask = kPointerAlignment - 1;
		kObjectAlignmentBits = kPointerSizeLog2;
		
		attached.add("Source");
		
		RootsStore rootsEnum = loadRoots();
		BuiltinsEnum builtinsEnum = loadBuiltins();
		JsRuntimesEnum jsRuns = loadJsRuntimes();
		RuntimesIntrinsicsStore runsIntrsStore = loadIntrsAndRuntimes();
		
		Enum predict = (Enum) mgr.addDataType(new CatchPrediction(), DataTypeConflictHandler.DEFAULT_HANDLER);
		Enum srcEnum = (Enum) mgr.addDataType(new ScriptSourceEnum(), DataTypeConflictHandler.DEFAULT_HANDLER);
		Enum typeEnum = (Enum) mgr.addDataType(new ScriptTypeEnum(), DataTypeConflictHandler.DEFAULT_HANDLER);
		Enum sptEnum = (Enum) mgr.addDataType(new SourcePositionTypeEnum(), DataTypeConflictHandler.DEFAULT_HANDLER);
		Enum rootsDt = (Enum) mgr.addDataType(new RootsEnum(rootsEnum), DataTypeConflictHandler.DEFAULT_HANDLER);
		Enum runsDt = (Enum) mgr.addDataType(new RuntimesEnum(runsIntrsStore), DataTypeConflictHandler.DEFAULT_HANDLER);
		Enum intrsDt = (Enum) mgr.addDataType(new IntrinsicsEnum(runsIntrsStore), DataTypeConflictHandler.DEFAULT_HANDLER);
		
		Enum typeofDt = (Enum) mgr.addDataType(new TypeOfEnum(), DataTypeConflictHandler.DEFAULT_HANDLER);
		
		EnumDataTypes enumsDt = new EnumDataTypes(rootsDt, runsDt, intrsDt, jsRuns, builtinsEnum, sptEnum, predict, typeofDt);
		EnumsStorage enums = new EnumsStorage(rootsEnum, runsIntrsStore);
		
		allocator = new ObjectsAllocator(enums, enumsDt, program, monitor);
	}
	
	private long pointerSizeAlign(long value) {
		return ((value + kPointerAlignmentMask) & ~kPointerAlignmentMask);
	}
	
	public void parse() throws Exception {
		monitor.setMessage("Parsing the binary...");
		
		reader.readNextUnsignedInt(); // skip magic dword

		long versionHash = reader.readNextUnsignedInt();
		long sourceHash = reader.readNextUnsignedInt();
		long cpuFeatures = reader.readNextUnsignedInt();
		long flagsHash = reader.readNextUnsignedInt();

		long reservCount = reader.readNextUnsignedInt();
		long reservSize = reservCount * 4;
		long codeStubsCount = reader.readNextUnsignedInt();
		long codeStubsSize = codeStubsCount * 4;
		long payloadSize = reader.readNextUnsignedInt();

		long c1 = reader.readNextUnsignedInt();
		long c2 = reader.readNextUnsignedInt();

		long payloadOffset = pointerSizeAlign(reader.getPointerIndex() + reservSize + codeStubsSize);

		int currSpace = 0;

		for (int i = 0; i < reservCount; ++i) {
			final AllocSpace space = AllocSpace.fromInt(currSpace);
			List<ReservObject> objects = reserv.get(space);

			if (objects == null) {
				objects = new ArrayList<>();
			}

			long size = reader.readNextUnsignedInt();

			objects.add(new ReservObject(size & 0x7FFFFFFFL, kPointerSize));
			
			reserv.put(space, objects);
			lastChunkIndex.put(space, 0);

			if ((size & 0x80000000L) >> 0x1F != 0) {
				currSpace++;
			}
		}

		for (int i = 0; i < codeStubsCount; ++i) {
			codeStubs.add(reader.readNextUnsignedInt());
		}
		// TODO: parse codeStubs if any
		
		reader.setPointerIndex(payloadOffset);

		ReservObject root = new ReservObject(kPointerSize, kPointerSize);
		readData(root, root.getSize(), AllocSpace.NEW_SPACE, 0);
		deserializeDeferredObjects();

		monitor.setMessage("Loading \"OLD_SPACE\" objects...");
		final List<ReservObject> chunks = reserv.get(AllocSpace.OLD_SPACE);
		for (final ReservObject objs : chunks) {
			loadSpaceObjects(objs);
		}
		
		monitor.setMessage("Loading done.");
	}
	
	public void postAllocate() throws MemoryBlockException, LockException, NotFoundException {
		allocator.postAllocate();
	}
	
	public ObjectsAllocator getAllocator() {
		return allocator;
	}
	
	public static int smiToInt(long value, int pointerSize) {
		if (pointerSize == 4) {
			return (int)(value >> 1L);
		}
		
		return (int)(value >> 32L);
	}
	
	private void loadSpaceObjects(final ReservObject spaceObjs) throws Exception {
		final ReservObject firstFunc = (ReservObject)spaceObjs.getAlignedObject(0);
		
		if (firstFunc == null) {
			return;
		}
		
		final ReservObject script = (ReservObject)firstFunc.getAlignedObject(SharedFunctionInfoStruct.getScriptOffset(kPointerSize));
		final ReservObject sharedFuncs = (ReservObject)script.getAlignedObject(12 * kPointerSize);
		int sfCount = sharedFuncs.getSmiInt(ArrayStruct.getArrayLengthOffset(kPointerSize));
		
		monitor.initialize(sfCount);
		
		FlatProgramAPI fpa = new FlatProgramAPI(program);
		
		final List<Address> doDisasm = new ArrayList<>();
		
		for (int i = 0; i < sfCount; ++i) {
			final ReservObject weakFunc = (ReservObject) sharedFuncs.getAlignedObject(ArrayStruct.getArrayHeaderSize(kPointerSize) + i * kPointerSize);
			final ReservObject func = (ReservObject) weakFunc.getAlignedObject(kPointerSize);
			
			SharedFunctionInfoStruct sf = SharedFunctionInfoStruct.getSharedFunctionInfo(allocator, i);
			if (sf == null) {
				sf = new SharedFunctionInfoStruct(func, allocator);
				Address sfiAddr = sf.allocate(allocator, monitor);
				mgr.addDataType(sf.toDataType(), DataTypeConflictHandler.DEFAULT_HANDLER);
			}

			final Address bcodeAddr = sf.getAddress();
			doDisasm.add(bcodeAddr);
			
			// handler addresses
			final HandlerTableStruct ht = sf.getHandlerTable();
			
			if (ht == null) {
				continue;
			}
			
			final List<HandlerTableItemStruct> htItems = ht.getItems();
			for (int j = 0; j < htItems.size(); ++j) {
				final HandlerTableItemStruct hti = htItems.get(j);
				
				doDisasm.add(bcodeAddr.add(hti.getOffset()));
				doDisasm.add(bcodeAddr.add(hti.getStartAddress()));
				doDisasm.add(bcodeAddr.add(hti.getEndAddress()));
				
				fpa.setPreComment(bcodeAddr.add(hti.getStartAddress()), String.format("try { // %s_handler_%d start", sf.getName(), j));
				fpa.setPreComment(bcodeAddr.add(hti.getEndAddress()), String.format("} // %s_handler_%d end", sf.getName(), j));
				
				fpa.createLabel(bcodeAddr.add(hti.getOffset()), String.format("%s_handler_%d", sf.getName(), j), true, SourceType.USER_DEFINED);
			}
			
			allocator.getMonitor().incrementProgress(1);
		}
		
		for (final Address dis : doDisasm) {
			ObjectsAllocator.disassemble(program, monitor, dis);
		}
	}
	
	private RootsStore loadRoots() {
		try {
			File file = Application.getModuleDataFile("v8_roots.json").getFile(false);
			final JsonArray rootsData = jsonArrayFromFile(file.getAbsolutePath());

			for (final var item : rootsData) {
				final JsonObject obj = item.getAsJsonObject();
				final String name = obj.get("Name").getAsString();
				final String type = obj.get("Type").getAsString();

				roots.add(new RootObject(name, type));
			}

			return new RootsStore(roots);
		} catch (IOException e) {
			e.printStackTrace();
			log.appendException(e);
			return null;
		}
		
	}
	
	public static JsonArray jsonArrayFromFile(final String file) throws IOException {
		if (file == null) {
			return null;
		}
		
		final byte[] bytes = Files.readAllBytes(Path.of(file));
		final String json = new String(bytes, "UTF8");
		
		final JsonElement tokens = JsonParser.parseString(json);
		return tokens.getAsJsonArray();
	}

	private BuiltinsEnum loadBuiltins() {
		try {
			File file = Application.getModuleDataFile("v8_builtins.json").getFile(false);
			final JsonArray rootsData = jsonArrayFromFile(file.getAbsolutePath());

			for (final var item : rootsData) {
				builtins.add(item.getAsString());
			}

			BuiltinsEnum result = new BuiltinsEnum(builtins);
			mgr.addDataType(result, DataTypeConflictHandler.DEFAULT_HANDLER);
			return result;
		} catch (IOException e) {
			e.printStackTrace();
			log.appendException(e);
			return null;
		}
	}
	
	private JsRuntimesEnum loadJsRuntimes() {
		try {
			File file = Application.getModuleDataFile("v8_jsruns.json").getFile(false);
			final JsonArray jsRuns = jsonArrayFromFile(file.getAbsolutePath());
			
			final List<String> items = new ArrayList<>();
			
			for (final var item : jsRuns) {
				final JsonObject obj = item.getAsJsonObject();
				
				items.add(obj.get("Name").getAsString());
			}
			
			JsRuntimesEnum result = new JsRuntimesEnum(items);
			mgr.addDataType(result, DataTypeConflictHandler.DEFAULT_HANDLER);
			return result;
		} catch (IOException e) {
			e.printStackTrace();
			log.appendException(e);
			return null;
		}
	}
	
	private RuntimesIntrinsicsStore loadIntrsAndRuntimes() {
		try {
			File file = Application.getModuleDataFile("v8_funcs.json").getFile(false);
			final JsonArray runsAndIntrs = jsonArrayFromFile(file.getAbsolutePath());
			
			final List<String> names = new ArrayList<>();
			final List<List<RuntimeFuncArg>> allArgs = new ArrayList<>();
			
			for (final var func : runsAndIntrs) {
				final JsonObject nameAndArgs = func.getAsJsonObject();

				String funcName = nameAndArgs.get("Name").getAsString();
				funcName = funcName.substring(1);

				JsonArray args = nameAndArgs.get("Args").getAsJsonArray();

				List<RuntimeFuncArg> funcArgs = new ArrayList<>();

				for (final var arg : args) {
					final JsonObject argObj = arg.getAsJsonObject();
					String name = argObj.get("Name").getAsString();

					String type = null;
					if (!name.equals("...")) {
						type = argObj.get("Type").getAsString();
					}

					funcArgs.add(new RuntimeFuncArg(name, type));
				}
				
				names.add(funcName);
				allArgs.add(funcArgs);
			}
			
			return new RuntimesIntrinsicsStore(names, allArgs);
		} catch (IOException e) {
			e.printStackTrace();
			log.appendException(e);
			return null;
		}
	}
	
	private void deserializeDeferredObjects() throws IOException {
		while (true) {
			int b = reader.readNextByte() & 0xFF;
			
			switch (b) {
			case 0x15:
			case 0x16:
			case 0x17: // kAlignmentPrefix
				nextAlignment = AllocationAlignment.fromInt(b - (0x15 - 1));
				break;
			case 0x18: // kSynchronize
				return;
			default: {
				AllocSpace space = AllocSpace.fromInt(b & 7); // kSpaceMask
				final ReservObject backObj = (ReservObject) getBackReferencedObject(space);
				
				long size = readInt() << kPointerSizeLog2;

				readData(backObj, size, space, kPointerSize);
			} break;
			}
		}
	}
	
	private void readData(ReservObject object, long size, AllocSpace space, long startInsert) throws IOException {
		long insertOff = startInsert;

		while (insertOff < size) {
			int b = reader.readNextByte() & 0xFF;

			long result = doAllSpaces(insertOff, b, object, AllocWhere.kNewObject, AllocHow.kPlain, AllocPoint.kStartOfObject);

			if (result != -1) {
				insertOff = result;
				continue;
			}

			result = doAllSpaces(insertOff, b, object, AllocWhere.kNewObject, AllocHow.kFromCode, AllocPoint.kInnerPointer);

			if (result != -1) {
				insertOff = result;
				continue;
			}

			result = doAllSpaces(insertOff, b, object, AllocWhere.kBackref, AllocHow.kPlain, AllocPoint.kStartOfObject);

			if (result != -1) {
				insertOff = result;
				continue;
			}

			result = doAllSpaces(insertOff, b, object, AllocWhere.kBackrefWithSkip, AllocHow.kPlain, AllocPoint.kStartOfObject);

			if (result != -1) {
				insertOff = result;
				continue;
			}

			result = doAllSpaces(insertOff, b, object, AllocWhere.kBackref, AllocHow.kFromCode, AllocPoint.kInnerPointer);

			if (result != -1) {
				insertOff = result;
				continue;
			}

			result = doAllSpaces(insertOff, b, object, AllocWhere.kBackrefWithSkip, AllocHow.kFromCode, AllocPoint.kInnerPointer);

			if (result != -1) {
				insertOff = result;
				continue;
			}

			result = doNewSpace(insertOff, b, object, AllocWhere.kRootArray, AllocHow.kPlain, AllocPoint.kStartOfObject);

			if (result != -1) {
				insertOff = result;
				continue;
			}

			result = doNewSpace(insertOff, b, object, AllocWhere.kExternalReference, AllocHow.kPlain, AllocPoint.kStartOfObject);

			if (result != -1) {
				insertOff = result;
				continue;
			}

			result = doNewSpace(insertOff, b, object, AllocWhere.kExternalReference, AllocHow.kFromCode, AllocPoint.kStartOfObject);

			if (result != -1) {
				insertOff = result;
				continue;
			}

			result = doNewSpace(insertOff, b, object, AllocWhere.kAttachedReference, AllocHow.kPlain, AllocPoint.kStartOfObject);

			if (result != -1) {
				insertOff = result;
				continue;
			}

			result = doNewSpace(insertOff, b, object, AllocWhere.kAttachedReference, AllocHow.kFromCode, AllocPoint.kStartOfObject);

			if (result != -1) {
				insertOff = result;
				continue;
			}

			result = doNewSpace(insertOff, b, object, AllocWhere.kAttachedReference, AllocHow.kFromCode, AllocPoint.kInnerPointer);

			if (result != -1) {
				insertOff = result;
				continue;
			}

			result = doNewSpace(insertOff, b, object, AllocWhere.kBuiltin, AllocHow.kPlain, AllocPoint.kStartOfObject);

			if (result != -1) {
				insertOff = result;
				continue;
			}

			result = doNewSpace(insertOff, b, object, AllocWhere.kBuiltin, AllocHow.kFromCode, AllocPoint.kStartOfObject);

			if (result != -1) {
				insertOff = result;
				continue;
			}

			switch (b & 0xFF) {
			case 0x0F: { // kSkip
				insertOff += readInt();
			} break;
			case 0x1B:
			case 0x1C: { // kInternalReferenceEncoded, kInternalReference
				throw new IOException("Unimplemented opcodes: 0x1B, 0x1C");
				// TODO: implement
			} 
			case 0x2F: // kNop
				return;
			case 0x4F: { // kNextChunk
				int newChunk = reader.readNextByte() & 0xFF;
				lastChunkIndex.put(space, newChunk);
				System.out.println(String.format("Switch to the space #%d", newChunk));
				// TODO: implement
			} break;
			case 0x6F: // kDeferred
				insertOff = size;
				break;
			case 0x18: // kSynchronize
				throw new IOException("Unimplemented opcode: 0x18");
				// TODO: implement
			case 0x1A: { // kVariableRawData
				long sizeInBytes = readInt();

				byte[] rawData = reader.readNextByteArray((int) sizeInBytes);

				object.addObject(insertOff, rawData);
			} break;
			case 0x19: { // kVariableRepeat
				int repeats = (int) readInt();
				final Object lastObj = object.getLastObject();
				
				insertOff = repeatObject(object, insertOff, lastObj, repeats);
			} break;
			case 0x35: // kOffHeapBackingStore
				throw new IOException("Unimplemented opcode: 0x35");
				// TODO: implement
			case 0x36: // kApiReference
				throw new IOException("Unimplemented opcode: 0x36");
				// TODO: implement
			case 0x15:
			case 0x16:
			case 0x17: // kAlignmentPrefix
				nextAlignment = AllocationAlignment.fromInt(b - (0x15 - 1));
				break;
			case 0xA0:
			case 0xA1:
			case 0xA2:
			case 0xA3:
			case 0xA4:
			case 0xA5:
			case 0xA6:
			case 0xA7:
			case 0xA8:
			case 0xA9:
			case 0xAA:
			case 0xAB:
			case 0xAC:
			case 0xAD:
			case 0xAE:
			case 0xAF:
			case 0xB0:
			case 0xB1:
			case 0xB2:
			case 0xB3:
			case 0xB4:
			case 0xB5:
			case 0xB6:
			case 0xB7:
			case 0xB8:
			case 0xB9:
			case 0xBA:
			case 0xBB:
			case 0xBC:
			case 0xBD:
			case 0xBE:
			case 0xBF: // kRootArrayConstantsWithSkip
				throw new IOException("Unimplemented opcodes: 0xA0-0xBF");
				// TODO: implement
			case 0x80:
			case 0x81:
			case 0x82:
			case 0x83:
			case 0x84:
			case 0x85:
			case 0x86:
			case 0x87:
			case 0x88:
			case 0x89:
			case 0x8A:
			case 0x8B:
			case 0x8C:
			case 0x8D:
			case 0x8E:
			case 0x8F:
			case 0x90:
			case 0x91:
			case 0x92:
			case 0x93:
			case 0x94:
			case 0x95:
			case 0x96:
			case 0x97:
			case 0x98:
			case 0x99:
			case 0x9A:
			case 0x9B:
			case 0x9C:
			case 0x9D:
			case 0x9E:
			case 0x9F: { // kRootArrayConstants
				object.addObject(insertOff, roots.get(b & 0x1F));
				insertOff += kPointerSize;
			} break;
			case 0x58:
			case 0x59:
			case 0x5A:
			case 0x5B:
			case 0x5C:
			case 0x5D:
			case 0x5E:
			case 0x5F: // kHotObjectsWithSkip
				throw new IOException("Unimplemented opcodes: 0x58-0x5F");
				// TODO: implement
			case 0x38:
			case 0x39:
			case 0x3A:
			case 0x3B:
			case 0x3C:
			case 0x3D:
			case 0x3E:
			case 0x3F: // kHotObject
				object.addObject(insertOff, hots.get(b & 7L));
				insertOff += kPointerSize;
				break;
			case 0xC0:
			case 0xC1:
			case 0xC2:
			case 0xC3:
			case 0xC4:
			case 0xC5:
			case 0xC6:
			case 0xC7:
			case 0xC8:
			case 0xC9:
			case 0xCA:
			case 0xCB:
			case 0xCC:
			case 0xCD:
			case 0xCE:
			case 0xCF:
			case 0xD0:
			case 0xD1:
			case 0xD2:
			case 0xD3:
			case 0xD4:
			case 0xD5:
			case 0xD6:
			case 0xD7:
			case 0xD8:
			case 0xD9:
			case 0xDA:
			case 0xDB:
			case 0xDC:
			case 0xDD:
			case 0xDE:
			case 0xDF: { // kFixedRawData
				int sizeInBytes = ((b & 0xFF) - (0xC0 - 1)) << kPointerSizeLog2;
				object.addObject(insertOff, reader.readNextByteArray(sizeInBytes));
				insertOff += sizeInBytes;
			} break;
			case 0xE0:
			case 0xE1:
			case 0xE2:
			case 0xE3:
			case 0xE4:
			case 0xE5:
			case 0xE6:
			case 0xE7:
			case 0xE8:
			case 0xE9:
			case 0xEA:
			case 0xEB:
			case 0xEC:
			case 0xED:
			case 0xEE:
			case 0xEF: { // kFixedRepeat
				int repeats = (b & 0xFF) - (0xE0 - 1);
				final Object lastObj = object.getLastObject();

				insertOff = repeatObject(object, insertOff, lastObj, repeats);
			} break;
			default:
				throw new IOException(String.format("Wrong JSC byte data: %02X", b));
			}
		}
	}
	
	private long repeatObject(final ReservObject insert, long insertOff, final Object lastObj, int count) {
		for (int i = 0; i < count; ++i) {
			insert.addObject(insertOff, lastObj);
			insertOff += kPointerSize;
		}
		
		return insertOff;
	}

	private long doAllSpaces(long insertOff, int val, ReservObject object, AllocWhere where, AllocHow how, AllocPoint within) throws IOException {
		final CaseState state = new CaseState(val, where, how, within);

		AllocSpace space = allSpaces(state);

		if (space == null) {
			return -1;
		}

		switch (space) {
		case OLD_SPACE:
		case CODE_SPACE:
		case MAP_SPACE:
		case LO_SPACE: {
			insertOff = readSpaceData(object, insertOff, state, null);
		}
			break;
		case NEW_SPACE: {
			insertOff = readSpaceData(object, insertOff, state, AllocSpace.NEW_SPACE);
		}
			break;
		}

		return insertOff;
	}

	private long doNewSpace(long insertOff, int val, ReservObject object, AllocWhere where,	AllocHow how, AllocPoint within) throws IOException {
		final CaseState state = new CaseState(val, where, how, within);

		if (!newSpace(state)) {
			return -1;
		}

		return readSpaceData(object, insertOff, state, AllocSpace.NEW_SPACE);
	}

	private long readSpaceData(ReservObject object, long insertOff, final CaseState state, AllocSpace space) throws IOException {
		space = (space == null) ? AllocSpace.fromInt(state.getValue() & 7) : space;

		AllocWhere where = state.getWhere();

		if (where.equals(AllocWhere.kNewObject) && state.getHow().equals(AllocHow.kPlain)
				&& state.getWithin().equals(AllocPoint.kStartOfObject)) {
			readObject(object, insertOff, space);
		} else {
			if (where.equals(AllocWhere.kNewObject)) {
				// TODO: implement
			} else if (where.equals(AllocWhere.kBackref)) {
				final Object backObj = getBackReferencedObject(AllocSpace.fromInt(state.getValue() & 7));
				object.addObject(insertOff, backObj);
			} else if (where.equals(AllocWhere.kBackrefWithSkip)) {
				// TODO: implement
			} else if (where.equals(AllocWhere.kRootArray)) {
				long id = readInt();
				final RootObject hotObj = roots.get((int) id);

				hots.put(lastHotIndex, hotObj);
				lastHotIndex = (lastHotIndex + 1) & 7;

				object.addObject(insertOff, hotObj);
			} else if (where.equals(AllocWhere.kPartialSnapshotCache)) {
				// TODO: implement
			} else if (where.equals(AllocWhere.kExternalReference)) {
				// TODO: implement
			} else if (where.equals(AllocWhere.kAttachedReference)) {
				long index = readInt();

				object.addObject(insertOff, attached.get((int) index));
			} else {
				long id = readInt();

				object.addObject(insertOff, builtins.get((int) id));
			}
		}

		return insertOff + kPointerSize;
	}

	private Object getBackReferencedObject(AllocSpace space) throws IOException {
		long backRef = readInt();

		long chunkIndex = 0L;
		long chunkOffset = 0L;

		if (space.equals(AllocSpace.LO_SPACE)) {
			// TODO: implement
		} else if (space.equals(AllocSpace.MAP_SPACE)) {
			// TODO: implement
		} else {
			if (is32Bit) {
				chunkIndex = (backRef & 0x1FFE0000L) >> 0x11L;
				chunkOffset = ((backRef & 0x1FFFFL) >> 0L) << kObjectAlignmentBits;
			} else {
				chunkIndex = (backRef & 0x1FFF0000L) >> 0x10L;
				chunkOffset = ((backRef & 0xFFFFL) >> 0L) << kObjectAlignmentBits;
			}
		}

		ReservObject reservObj = reserv.get(space).get((int) chunkIndex);
		Object backObj = reservObj.getAlignedObject(chunkOffset);
		hots.put(lastHotIndex, backObj);
		
		lastHotIndex = (lastHotIndex + 1) & 7;

		return backObj;
	}
	
	private int getMaximumFillToAlign() throws IOException {
		switch (nextAlignment) {
		case kWordAligned:
			return 0;
		case kDoubleAligned:
		case kDoubleUnaligned:
			return 8 - kPointerSize; // kDoubleSize - kPointerSize
		default:
			throw new IOException("Wrong alignment");
		}
	}
	
	private int getFillToAlign(long address) {
		if (nextAlignment.equals(AllocationAlignment.kDoubleAligned) && (address & 7L) != 0) { // kDoubleAlignmentMask
			return kPointerSize;  // kPointerSize
		}
		
		if (nextAlignment.equals(AllocationAlignment.kDoubleUnaligned) && (address & 7L) != 0) { // kDoubleAlignmentMask
			return 8 - kPointerSize; // kDoubleSize - kPointerSize
		}
		
		return 0;
	}
	
	private void createFillerObject(final ReservObject object, long address, int size) {
		if (size == 0) {
			object.addObject(address, null);
		}
		else if (size == kPointerSize) {  // kPointerSize
			object.addObject(address, roots.get(1)); // OnePointerFiller
		}
		else if (size == 2 * kPointerSize) { // 2 * kPointerSize
			object.addObject(address, roots.get(2)); // TwoPointerFiller
		}
		else {
			object.addObject(address, roots.get(0)); // FreeSpace
		}
	}
	
	private long precedeWithFiller(final ReservObject object, long address, int size) {
		createFillerObject(object, address, size);
		return address + size;
	}
	
	private void alignWithFiller(final ReservObject object, long address, long objectSize, int fillerSize) {
		int preFiller = getFillToAlign(address);
		
		if (preFiller != 0) {
			address = precedeWithFiller(object, address, preFiller);
			fillerSize -= preFiller;
		}
		
		if (fillerSize != 0) {
			createFillerObject(object, address + objectSize, fillerSize);
		}
	}

	private void readObject(final ReservObject object, long insertOff, AllocSpace space) throws IOException {
		long size = readInt() << kObjectAlignmentBits;
		
		int spaceChunk = lastChunkIndex.get(space);
		if (!nextAlignment.equals(AllocationAlignment.kWordAligned)) {
			final ReservObject reservObject = reserv.get(space).get(spaceChunk);
			long address = reservObject.getOffset();
			
			int filler = getMaximumFillToAlign();
			alignWithFiller(reservObject, address, size, filler);
			reservObject.setOffset(address + filler);
			nextAlignment = AllocationAlignment.kWordAligned;
		}

		final ReservObject reservObj = reserv.get(space).get(spaceChunk);
		
		long address = reservObj.getOffset();
		reservObj.setOffset(address + size);

		ReservObject newObj = new ReservObject(size, kPointerSize);
		reservObj.addObject(address, newObj);

		readData(newObj, size, space, 0);

		object.addObject(insertOff, newObj);
	}

	private long readInt() throws IOException {
		long answer = reader.readNextUnsignedInt();
		long bytesCount = (answer & 3L) + 1L;

		reader.setPointerIndex(reader.getPointerIndex() - 4L + bytesCount);
		long mask = 0xFFFFFFFFL;
		mask >>= 32L - (bytesCount << 3L);
		answer &= mask;
		answer >>= 2L;
		return answer;
	}

	private static AllocSpace allSpaces(final CaseState state) {
		return AllocSpace.fromInt(state.getValue() - caseStatement(state));
	}

	private static boolean newSpace(final CaseState state) {
		return AllocSpace.fromInt(state.getValue() - caseStatement(state)) == AllocSpace.NEW_SPACE;
	}

	private static int caseStatement(final CaseState state) {
		return state.getWhere().getValue() + state.getHow().getValue() + state.getWithin().getValue();
	}
}
