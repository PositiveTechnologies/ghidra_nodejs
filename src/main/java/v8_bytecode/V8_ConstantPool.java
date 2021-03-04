package v8_bytecode;

import ghidra.program.model.lang.ConstantPool;
import ghidra.program.model.listing.Program;
import v8_bytecode.allocator.JscParser;
import v8_bytecode.allocator.ObjectsAllocator;
import v8_bytecode.enums.RootsEnum;
import v8_bytecode.enums.TypeOfEnum;
import v8_bytecode.storage.ArrayStore;
import v8_bytecode.storage.RuntimesIntrinsicsStore;
import v8_bytecode.storage.ScopeInfoStore;
import v8_bytecode.storage.SharedFunctionStore;
import v8_bytecode.storage.FuncsStorage;
import v8_bytecode.storage.InstructionsStorage;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.program.model.data.Enum;

public class V8_ConstantPool extends ConstantPool {
	private final FuncsStorage funcsStorage;
	
	private final FlatProgramAPI fpa;
	private final DataTypeManager mgr;

	public V8_ConstantPool(Program program) {
		fpa = new FlatProgramAPI(program);
		
		mgr = program.getDataTypeManager();

		funcsStorage = FuncsStorage.load(program);
	}

	@Override
	public Record getRecord(long[] ref) {
		Record res = new Record();
		String tmp = "";
		int tmpLen = 0;
		long address = ref[0];
		int index = (int) ref[1];
		int indexType = (int) ref[2];
		
		// System.out.println(String.format("%04X %04X", address, index));
		switch (indexType) {
		case 0: { // constant pool
			final Object cpItem = funcsStorage.getConstItem(fpa.toAddr(address), index);
			
			if (cpItem instanceof String) {
				res.tag = ConstantPool.STRING_LITERAL;
				res.type = new PointerDataType(CharDataType.dataType);
				res.byteData = ((String)cpItem).getBytes();
			} else if (cpItem instanceof Integer) {
		          res.tag = ConstantPool.PRIMITIVE;
		          res.type = IntegerDataType.dataType;
		          res.value = (Integer)cpItem;
		          res.token = "int";
			} else if (cpItem instanceof Long) {
		          res.tag = ConstantPool.PRIMITIVE;
		          res.type = LongLongDataType.dataType;
		          res.value = (Long)cpItem;
		          res.token = "longlong";
			} else if (cpItem instanceof Double) {
				res.tag = ConstantPool.PRIMITIVE;
				res.type = DoubleDataType.dataType;

				final int[] halfs = ObjectsAllocator.doubleToInts((Double)cpItem);
				res.value = (((long)halfs[1]) << 32 ) + (halfs[0] & 0xffffffffL);
				res.token = "double";
			} else if (cpItem instanceof RootObject) {
				res.tag = ConstantPool.PRIMITIVE;
				res.type = mgr.getRootCategory().getDataType(RootsEnum.NAME);
				res.value = funcsStorage.getRoots().fromString((RootObject)cpItem);
				res.token = ((RootObject)cpItem).getName();
			} else if (cpItem instanceof SharedFunctionStore) {
				final Address funcAddr = fpa.toAddr(((SharedFunctionStore)cpItem).getAddress());
				res.tag = ConstantPool.POINTER_METHOD;
				res.type = new PointerDataType(VoidDataType.dataType);
				res.token = fpa.getFunctionAt(funcAddr).getName();
			} else if (cpItem instanceof ArrayStore){
				res.tag = ConstantPool.POINTER_FIELD;
				res.type = mgr.getRootCategory().getDataType(((ArrayStore)cpItem).getName());
				res.token = ((ArrayStore)cpItem).getName();
			} else if (cpItem instanceof ScopeInfoStore) {
				res.tag = ConstantPool.POINTER_FIELD;
				res.type = mgr.getRootCategory().getDataType(((ScopeInfoStore)cpItem).getName());
				res.token = ((ScopeInfoStore)cpItem).getName();
			} else {
				//System.out.println(cpItem);
			}
		} break;
		case 1: // intrinsics
		case 2: { // runtimes
			final RuntimesIntrinsicsStore runsIntrsStore = funcsStorage.getRuntimesIntrinsicsStore();
			res.tag = ConstantPool.POINTER_METHOD;
			res.type = new PointerDataType(VoidDataType.dataType);			
			res.token = (indexType == 1) ? runsIntrsStore.getIntrinsicName(index) : runsIntrsStore.getRuntimeName(index);
		} break;
		case 3: { // context slot
			final InstructionsStorage instrStorage = InstructionsStorage.load(fpa.getCurrentProgram(), address);
			
			if (instrStorage == null) {
				break;
			}
			
			res.tag = ConstantPool.POINTER_METHOD;
			res.type = new PointerDataType(VoidDataType.dataType);
			res.token = instrStorage.getScopeInfo().getContextVar(index).getName();
		} break;
		case 4: {
			final Enum typeOf = (Enum) mgr.getRootCategory().getDataType(TypeOfEnum.NAME);
			
			res.tag = ConstantPool.PRIMITIVE;
			res.type = typeOf;
			res.value = index;
			res.token = typeOf.getName(index);
		} break;
		case 5: {
			final Object cpItem = funcsStorage.getConstItem(fpa.toAddr(address), index);
			
			final long val;
			if (cpItem instanceof Integer) {
				val = JscParser.smiToInt((int)cpItem, ObjectsAllocator.getPointerSize(fpa.getCurrentProgram()));
			} else { // item instanceof Long
				val = JscParser.smiToInt((long)cpItem, ObjectsAllocator.getPointerSize(fpa.getCurrentProgram()));	
			}
			
			res.tag = ConstantPool.PRIMITIVE;
	        res.type = LongLongDataType.dataType;
	        res.value = val;
	        res.token = "longlong";
		} break;
		}

		return res;
	}
}
