package v8_bytecode.allocator;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;
import java.util.SortedMap;
import java.util.TreeMap;

import ghidra.framework.store.LockException;
import ghidra.program.disassemble.Disassembler;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.CharDataType;
import ghidra.program.model.data.DWordDataType;
import ghidra.program.model.data.DataUtilities;
import ghidra.program.model.data.DoubleDataType;
import ghidra.program.model.data.LongLongDataType;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.DataUtilities.ClearDataMode;
import ghidra.program.model.data.StringDataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.VoidDataType;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.mem.MemoryBlockException;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.NotFoundException;
import ghidra.util.task.TaskMonitor;
import v8_bytecode.EnumsStorage;
import v8_bytecode.ReservObject;
import v8_bytecode.RootObject;
import v8_bytecode.enums.EnumDataTypes;
import v8_bytecode.storage.SharedFunctionStore;
import v8_bytecode.storage.FuncsStorage;
import v8_bytecode.structs.ArrayStruct;
import v8_bytecode.structs.ScopeInfoStruct;
import v8_bytecode.structs.SharedFunctionInfoStruct;
import v8_bytecode.structs.TupleStruct;

public final class ObjectsAllocator {
	private MemoryBlock bcBlock; // bytecode
	public static final long CODE_BASE = 0x10000000L;
	private static final int CODE_MAX = 0x00100000;

	private MemoryBlock bciBlock; // bytecode info
	private static final long CODEI_BASE = 0x20000000L;
	private static final int CODEI_MAX = 0x00100000;

	private MemoryBlock arBlock; // arrays
	private static final long ARRAY_BASE = 0x21000000L;
	private static final int ARRAY_MAX = 0x00100000;

	private MemoryBlock tpBlock; // tuples
	private static final long TUPLS_BASE = 0x22000000L;
	private static final int TUPLS_MAX = 0x00100000;
	
	private MemoryBlock cpBlock; // constant pools
	private static final long CPOOLS_BASE = 0x23000000L;
	private static final int CPOOLS_MAX = 0x00100000;

	private MemoryBlock siBlock; // scope info
	private static final long SCOPES_BASE = 0x24000000L;
	private static final int SCOPES_MAX = 0x00100000;

	private MemoryBlock sfBlock; // shared function
	private static final long SFUNCS_BASE = 0x25000000L;
	private static final int SFUNCS_MAX = 0x00100000;
	
	private MemoryBlock stBlock; // strings
	private static final long STRINGS_BASE = 0x26000000L;
	private static final int STRINGS_MAX = 0x00100000;
	
	public static final int kMetaMap = 0;
	
	private TaskMonitor monitor;
	private Memory mem;
	private final FlatProgramAPI fpa;
	private final EnumsStorage enums;
	private final EnumDataTypes enumsDt;
	private final FuncsStorage storage;
	
	private final Map<MemoryBlock, AllocationInfoLast> allocsLast;
	private final Map<MemoryBlock, AllocationInfoNew> allocsNew;
	
	private final Map<IAllocatable, Address> allocated;
	
	private final Set<ReservObject> createdArrays = new HashSet<>();
	private final Map<ReservObject, ScopeInfoStruct> createdScopes = new HashMap<>();
	private final SortedMap<Integer, SharedFunctionInfoStruct> createdSharedFuncs = new TreeMap<>();
	private final Set<ReservObject> createdTuples = new HashSet<>();
	
	public ObjectsAllocator(final EnumsStorage enums, final EnumDataTypes enumsDt, Program program, TaskMonitor monitor) throws Exception {
		this.enums = enums;
		this.enumsDt = enumsDt;
		this.mem = program.getMemory();
		this.monitor = monitor;
		
		allocsLast = new HashMap<>();
		allocsNew = new HashMap<>();
		allocated = new HashMap<>();
		
		storage = FuncsStorage.create(program, enums);
		
		fpa = new FlatProgramAPI(program);
		
		byte[] fillBytes = new byte[CODE_MAX];
		Arrays.fill(fillBytes, (byte) 0x95);
		bcBlock = fpa.createMemoryBlock(".text", fpa.toAddr(CODE_BASE), fillBytes, false);
		bcBlock.setExecute(true);
		bcBlock.setRead(true);
		bcBlock.setWrite(false);
		bcBlock.setVolatile(false);
		allocsLast.put(bcBlock, new AllocationInfoLast(bcBlock));
		
		bciBlock = fpa.createMemoryBlock(".bcods", fpa.toAddr(CODEI_BASE), new byte[CODEI_MAX], false);
		bciBlock.setExecute(false);
		bciBlock.setRead(true);
		bciBlock.setWrite(false);
		bciBlock.setVolatile(false);
		allocsNew.put(bciBlock, new AllocationInfoNew());
		
		arBlock = fpa.createMemoryBlock(".arrs", fpa.toAddr(ARRAY_BASE), new byte[ARRAY_MAX], false);
		arBlock.setExecute(false);
		arBlock.setRead(true);
		arBlock.setWrite(false);
		arBlock.setVolatile(false);
		allocsNew.put(arBlock, new AllocationInfoNew());
		
		tpBlock = fpa.createMemoryBlock(".tupls", fpa.toAddr(TUPLS_BASE), new byte[TUPLS_MAX], false);
		tpBlock.setExecute(false);
		tpBlock.setRead(true);
		tpBlock.setWrite(false);
		tpBlock.setVolatile(false);
		allocsNew.put(tpBlock, new AllocationInfoNew());
		
		cpBlock = fpa.createMemoryBlock(".cpool", fpa.toAddr(CPOOLS_BASE), new byte[CPOOLS_MAX], false);
		cpBlock.setExecute(false);
		cpBlock.setRead(true);
		cpBlock.setWrite(false);
		cpBlock.setVolatile(false);
		allocsNew.put(cpBlock, new AllocationInfoNew());
		
		siBlock = fpa.createMemoryBlock(".scope", fpa.toAddr(SCOPES_BASE), new byte[SCOPES_MAX], false);
		siBlock.setExecute(false);
		siBlock.setRead(true);
		siBlock.setWrite(true);
		siBlock.setVolatile(false);
		allocsNew.put(siBlock, new AllocationInfoNew());
		
		sfBlock = fpa.createMemoryBlock(".sfunc", fpa.toAddr(SFUNCS_BASE), new byte[SFUNCS_MAX], false);
		sfBlock.setExecute(false);
		sfBlock.setRead(true);
		sfBlock.setWrite(false);
		sfBlock.setVolatile(false);
		allocsNew.put(sfBlock, new AllocationInfoNew());
		
		stBlock = fpa.createMemoryBlock(".str", fpa.toAddr(STRINGS_BASE), new byte[STRINGS_MAX], false);
		stBlock.setExecute(false);
		stBlock.setRead(true);
		stBlock.setWrite(false);
		stBlock.setVolatile(false);
		allocsLast.put(stBlock, new AllocationInfoLast(stBlock));
	}
	
	public int getPointerSize() {
		return getPointerSize(fpa.getCurrentProgram());
	}
	
	public static int getPointerSize(Program program) {
		final String descr = program.getLanguage().getLanguageDescription().getVariant();
		return descr.equalsIgnoreCase("x32") ? 4 : 8;
	}
	
	public TaskMonitor getMonitor() {
		return monitor;
	}
	
	public FlatProgramAPI getFpa() {
		return fpa;
	}
	
	public Program getProgram() {
		return fpa.getCurrentProgram();
	}
	
	public int getCreatedArraysSize() {
		return createdArrays.size();
	}

	public void addToCreatedArrays(final ReservObject obj) {
		createdArrays.add(obj);
	}
	
	public int getCreatedScopesSize() {
		return createdScopes.size();
	}

	public void addToCreatedScopes(final ReservObject obj, final ScopeInfoStruct scopeInfo) {
		createdScopes.put(obj, scopeInfo);
	}
	
	public ScopeInfoStruct getScopeInfoByObject(final ReservObject obj) {
		return createdScopes.get(obj);
	}
	
	public void addToCreatedSharedFuncs(int funcId, final SharedFunctionInfoStruct sharedFunc) {
		createdSharedFuncs.put(funcId, sharedFunc);
	}
	
	public SharedFunctionInfoStruct getCreatedSharedFunc(int funcIndex) {
		return createdSharedFuncs.get(funcIndex);
	}
	
	public int getCreatedTuplesSize() {
		return createdTuples.size();
	}

	public void addToCreatedTuples(final ReservObject obj) {
		createdTuples.add(obj);
	}
	
	// arrays
	public MemoryBlock getArraysBlock() {
		return arBlock;
	}
	
	public long getNewArrayAddress() {
		return allocsNew.get(arBlock).getNewAddress();
	}
	
	public void incNewArrayAddress(int size) {
		allocsNew.get(arBlock).incNewAddress(size);
	}
	
	// bytecode info
	public MemoryBlock getBytecodesInfoBlock() {
		return bciBlock;
	}
	
	public long getNewBytecodeInfoAddress() {
		return allocsNew.get(bciBlock).getNewAddress();
	}
	
	public void incNewBytecodeInfoAddress(int size) {
		allocsNew.get(bciBlock).incNewAddress(size);
	}
	
	// scope infos
	public MemoryBlock getScopesInfoBlock() {
		return siBlock;
	}
	
	public long getNewScopeInfoAddress() {
		return allocsNew.get(siBlock).getNewAddress();
	}
	
	public void incNewScopeInfoAddress(int size) {
		allocsNew.get(siBlock).incNewAddress(size);
	}
	
	// shared funcs
	public MemoryBlock getSharedFunctionsInfoBlock() {
		return sfBlock;
	}
	
	public long getNewSharedFunctionInfoAddress() {
		return allocsNew.get(sfBlock).getNewAddress();
	}
	
	public void incNewSharedFunctionInfoAddress(int size) {
		allocsNew.get(sfBlock).incNewAddress(size);
	}
	
	// tuples
	public MemoryBlock getTuplesBlock() {
		return tpBlock;
	}
	
	public long getNewTupleAddress() {
		return allocsNew.get(tpBlock).getNewAddress();
	}
	
	public void incNewTupleAddress(int size) {
		allocsNew.get(tpBlock).incNewAddress(size);
	}
	
	// constant pools
	public MemoryBlock getConstantPoolsBlock() {
		return cpBlock;
	}
	
	public long getNewConstantPoolAddress() {
		return allocsNew.get(cpBlock).getNewAddress();
	}
	
	public void incNewConstantPoolAddress(int size) {
		allocsNew.get(cpBlock).incNewAddress(size);
	}
	
	public Address allocateInCode(final Object data) throws Exception {
		return allocateData(allocsLast.get(bcBlock), data);
	}
	
	public Address allocateInStrings(final Object data) throws Exception {
		Address result = allocateData(allocsLast.get(stBlock), data);
		allocateData(allocsLast.get(stBlock), (byte)0);
		setDataString(result);
		return result;
	}
	
	public void postAllocate() throws MemoryBlockException, LockException, NotFoundException {
		monitor.setMessage("Post allocation...");
		int transId = fpa.getCurrentProgram().startTransaction("Post allocation");
		for (Entry<MemoryBlock, AllocationInfoLast> ai : allocsLast.entrySet()) {
			Address tmp = ai.getKey().getStart().add(ai.getValue().getLastAddress());
			
			if (!ai.getKey().getStart().equals(tmp)) {
				mem.split(ai.getKey(), tmp);
			}
			
			mem.removeBlock(mem.getBlock(tmp), monitor);
		}
		
		for (Entry<MemoryBlock, AllocationInfoNew> ai : allocsNew.entrySet()) {
			Address tmp = ai.getKey().getStart().add(ai.getValue().getNewAddress());
			
			if (!ai.getKey().getStart().equals(tmp)) {
				mem.split(ai.getKey(), tmp);
			}
			
			mem.removeBlock(mem.getBlock(tmp), monitor);
		}
		
		fpa.getCurrentProgram().endTransaction(transId, true);
		monitor.setMessage("Post allocation finished.");
		
		storage.store(fpa.getCurrentProgram());
	}
	
	public Object convertReservObject(final ReservObject obj) throws Exception {
		final RootObject typeObj = (RootObject) obj.getAlignedObject(kMetaMap);
		final String type = typeObj.getName();
		
		int kPointerSize = getPointerSize();
		
		switch (type) {
		case "OneByteInternalizedString":
		case "OneByteString": {
			byte[] result = reservObjectToBytes(obj, 2, false);
			return new String(result);
		}
		case "InternalizedString": {
			byte[] result = reservObjectToBytes(obj, 2, true);
			return new String(result, StandardCharsets.UTF_16LE);
		}
		case "FixedCOWArray": {
			int count = (int) (obj.getSize() - kPointerSize) / 4;
			
			int[] result = new int[count];
			for (int i = 0; i < result.length; ++i) {
				result[i] = obj.getInt(kPointerSize + i * 4);
			}
			
			return result;
		}
		case "SharedFunctionInfo": {
			return new SharedFunctionInfoStruct(obj, this);
		}
		case "ConsOneByteString": {
			return convertConsOneByteString(obj);
		}
		default: {
			throw new Exception(type);
		}
		}
	}
	
	public byte[] reservObjectToBytes(final ReservObject obj, int lenDwordIndex, boolean is16le) {
		int pointerSize = getPointerSize();
		
		int len = obj.getSmiInt(lenDwordIndex * pointerSize) * (is16le ? 2 : 1);
		byte[] result = new byte[len];
		
		for (int i = 0; i < len; i += 4) {
			byte[] tmp = intToBytes(obj.getInt((lenDwordIndex + 1) * pointerSize + i));
			
			if ((i + 0) < len) {
				result[i + 0] = tmp[0];
			} else {
				break;
			}
			if ((i + 1) < len) {
				result[i + 1] = tmp[1];
			} else {
				break;
			}
			if ((i + 2) < len) {
				result[i + 2] = tmp[2];
			} else {
				break;
			}
			if ((i + 3) < len) {
				result[i + 3] = tmp[3];
			} else {
				break;
			}
		}
		
		return result;
	}
	
	public String convertConsOneByteString(final Object obj) throws Exception {
		if (obj == null) {
			return "";
		} else if (obj instanceof String) {
			return (String)obj;
		} else if (obj instanceof RootObject) {
			return ((RootObject)obj).getName();
		} else if (obj instanceof ReservObject) {
			final RootObject typeObj = (RootObject) ((ReservObject)obj).getAlignedObject(kMetaMap);
			final String type = typeObj.getName();
			
			int kPointerSize = getPointerSize();
			
			if (type.equals("OneByteInternalizedString") || type.equals("OneByteString")) {
				return (String) convertReservObject((ReservObject)obj);
			} else if (type.equals("ConsOneByteString")) {
				final ReservObject rObj = (ReservObject)obj;
				String left = convertConsOneByteString(rObj.getAlignedObject(3 * kPointerSize)); // meta, hash, size
				return left + convertConsOneByteString(rObj.getAlignedObject(4 * kPointerSize));
			}
		}
		
		return "";
	}
	
	public Object prepareForAlloc(final Object cpObj) throws Exception {
		if ((cpObj instanceof Integer) || (cpObj instanceof Long) || (cpObj instanceof RootObject)) {
			return cpObj;
		} else if (cpObj instanceof ReservObject) {
			final ReservObject rObj = (ReservObject)cpObj;
			final RootObject rType = (RootObject) rObj.getAlignedObject(kMetaMap);
			
			int kPointerSize = getPointerSize();
			
			switch (rType.getName()) {
			case "OneByteInternalizedString":
			case "OneByteString":
			case "InternalizedString":
				return convertReservObject(rObj);
			case "SharedFunctionInfo": {
				SharedFunctionInfoStruct sf = SharedFunctionInfoStruct.getSharedFunctionInfo(this, SharedFunctionInfoStruct.getFunctionIndex(rObj, kPointerSize));
				
				if (sf == null) {
					sf = new SharedFunctionInfoStruct(rObj, this);
				}
				
				return sf;
			}
			case "ScopeInfo": {
				ScopeInfoStruct result = ScopeInfoStruct.fromReservObject(this, rObj);
				
				if (result == null) {
					result = new ScopeInfoStruct(rObj, this);
				}
				
				return result;
			}
			case "FixedArray":
			case "FixedCOWArray": {
				return new ArrayStruct(rObj, this);
			}
			case "Tuple2": {
				return new TupleStruct(rObj, 2, this);
			}
			case "Tuple3": {
				return new TupleStruct(rObj, 3, this);
			}
			case "HeapNumber": {
				return twoIntsToDouble(rObj.getInt(kPointerSize), rObj.getInt(kPointerSize + 4));
			}
			default: {
				throw new Exception(String.format("Implement %s type!", rType.getName()));
			}
			}
		} else {
			throw new Exception(String.format("Implement %s prepare!", cpObj.getClass().getName()));
		}
	}
	
	public Address allocateData(final AllocationInfoLast info, final Object data) throws Exception {
		Address result = info.getAllocAddress();
		
		if (data instanceof byte[]) {
			mem.setBytes(result, (byte[])data);
			info.incLastAddress(((byte[])data).length);
		} else if (data instanceof String) {
			byte[] tmp = ((String)data).getBytes();
			mem.setBytes(result, tmp);
			info.incLastAddress(tmp.length);
		} else if (data instanceof RootObject) {
			byte[] tmp = intToBytes(enums.getRoots().fromString((RootObject)data));
			mem.setBytes(result, tmp);
			info.incLastAddress(tmp.length);
		} else if (data instanceof Byte) {
			mem.setBytes(result, new byte[] {(byte)data});
			info.incLastAddress(1);
		} else if (data instanceof Integer) {
			mem.setBytes(result, intToBytes((int)data));
			info.incLastAddress(4);
		} else if (data instanceof Long) {
			mem.setBytes(result, longToBytes((long)data));
			info.incLastAddress(8);
		} else if (data instanceof Double) {
			mem.setBytes(result, doubleToBytes((double)data));
			info.incLastAddress(8);
		} else if (data instanceof Address) {
			mem.setBytes(result, intToBytes((int)((Address)data).getOffset()));
			info.incLastAddress(4);
		} else if (data instanceof IAllocatable) {
			Address tmp;
			if (allocated.containsKey(data)) {
				tmp = allocated.get(data);
			} else {
				tmp = ((IAllocatable)data).allocate(this, monitor);
			}

			result = allocateData(info, tmp);
		} else if (data instanceof ReservObject) {
			final Object convData = convertReservObject((ReservObject)data);
			return allocateData(info, convData);
		} else {
			throw new Exception("Cannot allocate data");
		}
		
		return result;
	}
	
	public void addStructureField(final Structure s, final Object cpObj, final String itemName) throws Exception {
		if (cpObj instanceof Integer) {
			s.add(DWordDataType.dataType, -1, itemName, null);
		} else if (cpObj instanceof Long) {
			s.add(LongLongDataType.dataType, -1, itemName, null);
		} else if (cpObj instanceof Double) {
			s.add(DoubleDataType.dataType, -1, itemName, null);
		} else if (cpObj instanceof String) {
			s.add(new PointerDataType(CharDataType.dataType), -1, itemName, null);
		} else if (cpObj instanceof RootObject) {
			s.add(getEnumDataTypes().getRoots(), -1, itemName, null);
		} else if (cpObj instanceof IAllocatable) {
			s.add(new PointerDataType(VoidDataType.dataType), -1, itemName, null);
		} else {
			throw new Exception(String.format("Implement %s structure field type!", cpObj.getClass().getName()));
		}
	}
	
	public void addToAllocated(final IAllocatable obj, final Address addr) {
		allocated.put(obj, addr);
	}
	
	public void addToSharedFunctions(final SharedFunctionStore func) {
		storage.addToSharedFunctions(func);
	}
	
	public EnumDataTypes getEnumDataTypes() {
		return enumsDt;
	}
	
	public void setDataStruct(Address addr, IAllocatable dt) throws CodeUnitInsertionException, DuplicateNameException, IOException {
		DataUtilities.createData(fpa.getCurrentProgram(), addr, dt.toDataType(), -1, true, ClearDataMode.CLEAR_ALL_UNDEFINED_CONFLICT_DATA);
	}
	
	private void setDataString(Address addr) throws CodeUnitInsertionException {
		DataUtilities.createData(fpa.getCurrentProgram(), addr, StringDataType.dataType, -1, true, ClearDataMode.CLEAR_ALL_UNDEFINED_CONFLICT_DATA);
	}
	
	public static void disassemble(Program program, TaskMonitor monitor, Address start) {
		Disassembler disasm = Disassembler.getDisassembler(program, monitor, null);
		disasm.setRepeatPatternLimit(-1);
		disasm.disassemble(start, null, true);
	}
	
	public static double twoIntsToDouble(int x1, int x2) {
		ByteBuffer buffer = ByteBuffer.allocate(Double.BYTES);
		buffer.order(ByteOrder.LITTLE_ENDIAN);
		buffer.putInt(x1);
		buffer.putInt(x2);
		buffer.flip();
		return buffer.getDouble();
	}
	
	public static int[] doubleToInts(double x) {
		ByteBuffer buffer = ByteBuffer.allocate(Double.BYTES);
		buffer.order(ByteOrder.LITTLE_ENDIAN);
		buffer.putDouble(x);
		buffer.flip();
		
		int[] result = new int[2];
		
		result[0] = buffer.getInt();
		result[1] = buffer.getInt();
		
		return result;
	}
	
	public static byte[] doubleToBytes(double x) {
		ByteBuffer buffer = ByteBuffer.allocate(Double.BYTES);
		buffer.order(ByteOrder.LITTLE_ENDIAN);
		buffer.putDouble(x);
		buffer.flip();
	    return buffer.array();
	}
//	
//	public static byte[] platformDwordToBytes(long x) {
//		if (JscParser.kPointerSize == 4) {
//			return intToBytes((int)x);
//		}
//		
//		return longToBytes(x);
//	}
	
	public static byte[] intToBytes(int x) {
		ByteBuffer buffer = ByteBuffer.allocate(Integer.BYTES);
		buffer.order(ByteOrder.LITTLE_ENDIAN);
		buffer.putInt(x);
		return buffer.array();
	}
	
	private static byte[] longToBytes(long x) {
		ByteBuffer buffer = ByteBuffer.allocate(Long.BYTES);
		buffer.order(ByteOrder.LITTLE_ENDIAN);
		buffer.putLong(x);
		return buffer.array();
	}
	
	public static int[] bytesToInts(byte[] data, int offset) {
		int count = (data.length - offset) / 4;
		ByteBuffer buffer = ByteBuffer.wrap(data, offset, data.length - offset);
		buffer.order(ByteOrder.LITTLE_ENDIAN);
		
		int[] result = new int[count];
		
		for (int i = 0; i < count; ++i) {
			result[i] = buffer.getInt();
		}
		
		return result;
	}
	
//	private static int bytesToInt(byte[] data, int offset) {
//		ByteBuffer buffer = ByteBuffer.wrap(data, offset, data.length - offset);
//		buffer.order(ByteOrder.LITTLE_ENDIAN);
//		return buffer.getInt();
//	}
//	
//	private static long bytesToLong(byte[] data, int offset) {
//		ByteBuffer buffer = ByteBuffer.wrap(data, offset, data.length - offset);
//		buffer.order(ByteOrder.LITTLE_ENDIAN);
//		return buffer.getLong();
//	}
}
