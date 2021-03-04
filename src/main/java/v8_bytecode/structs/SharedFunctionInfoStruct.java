package v8_bytecode.structs;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

import ghidra.program.model.address.Address;
import ghidra.program.model.data.CharDataType;
import ghidra.program.model.data.DWordDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.IntegerDataType;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.VoidDataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Function.FunctionUpdateType;
import ghidra.program.model.listing.LocalVariableImpl;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.task.TaskMonitor;
import v8_bytecode.ReservObject;
import v8_bytecode.RootObject;
import v8_bytecode.allocator.IAllocatable;
import v8_bytecode.allocator.ObjectsAllocator;
import v8_bytecode.allocator.SharedFunctionsAllocator;
import v8_bytecode.storage.SharedFunctionStore;

public final class SharedFunctionInfoStruct implements IAllocatable {
	private final Structure s;
	
	private ScopeInfoStruct scopeInfo1s;
	private Object scopeInfo2s;
	private final BytecodeStruct bytecode;
	private Object feedback;
	private final String codeOffset;
	private Object nameObject;
	private final String constructStub;
	private final RootObject instanceClass;
	private final int debugInfo;
	private Object ident;
	private Object preParsed;
	private final int functionLiteralId;
	private final int functionLength;
	private final int formalParameterCount;
	private final int expectedNofProperties;
	private final int startPositionAndType;
	private final int endPosition;
	private final int functionTokenPosition;
	private final int compilerHints;
	
	private String name = "";
	private final int size;
	private final SharedFunctionsAllocator sfAllocator;
	
	public final long kCodeOffset;
	public final long kNameOffset;
	public final long kScopeInfoOffset;
	public final long kOuterScopeInfoOffset;
	public final long kConstructStubOffset;
	public final long kInstanceClassNameOffset;
	public final long kFunctionDataOffset;
	public final long kScriptOffset;
	public final long kDebugInfoOffset;
	public final long kFunctionIdentifierOffset;
	public final long kFeedbackMetadataOffset;
	public final long kPreParsedScopeDataOffset;
	public final long kFunctionLiteralIdOffset;
	public final long kLengthOffset;
	public final long kFormalParameterCountOffset;
	public final long kExpectedNofPropertiesOffset;
	public final long kStartPositionAndTypeOffset;
	public final long kEndPositionOffset;
	public final long kFunctionTokenPositionOffset;
	public final long kCompilerHintsOffset;

	public SharedFunctionInfoStruct(final ReservObject obj, final ObjectsAllocator allocator) throws Exception {
		int pointerSize = allocator.getPointerSize();
		
		kCodeOffset = ObjectsAllocator.kMetaMap + pointerSize;
		kNameOffset = kCodeOffset + pointerSize;
		kScopeInfoOffset = kNameOffset + pointerSize;
		kOuterScopeInfoOffset = kScopeInfoOffset + pointerSize;
		kConstructStubOffset = kOuterScopeInfoOffset + pointerSize;
		kInstanceClassNameOffset = kConstructStubOffset + pointerSize;
		kFunctionDataOffset = kInstanceClassNameOffset + pointerSize;
		kScriptOffset = kFunctionDataOffset + pointerSize;
		kDebugInfoOffset = kScriptOffset + pointerSize;
		kFunctionIdentifierOffset = kDebugInfoOffset + pointerSize;
		kFeedbackMetadataOffset = kFunctionIdentifierOffset + pointerSize;
		kPreParsedScopeDataOffset = kFeedbackMetadataOffset + pointerSize;
		kFunctionLiteralIdOffset = kPreParsedScopeDataOffset + pointerSize;
		kLengthOffset = kFunctionLiteralIdOffset + 4;
		kFormalParameterCountOffset = kLengthOffset + 4;
		kExpectedNofPropertiesOffset = kFormalParameterCountOffset + 4;
		kStartPositionAndTypeOffset = kExpectedNofPropertiesOffset + 4;
		kEndPositionOffset = kStartPositionAndTypeOffset + 4;
		kFunctionTokenPositionOffset = kEndPositionOffset + 4;
		kCompilerHintsOffset = kFunctionTokenPositionOffset + 4;
		
		sfAllocator = new SharedFunctionsAllocator(allocator);
		
		functionLiteralId = obj.getInt(kFunctionLiteralIdOffset);
		allocator.addToCreatedSharedFuncs(functionLiteralId, this);

		allocator.getMonitor().setMessage(String.format("Creating function #%d", functionLiteralId));
		
		s = new StructureDataType(String.format("SharedFunctionInfo%d", functionLiteralId), 0);

		codeOffset = (String) obj.getAlignedObject(kCodeOffset);
		s.add(allocator.getEnumDataTypes().getBuiltins(), -1, "CodeOffset", null); // 4
		
		nameObject = obj.getAlignedObject(kNameOffset);
		if (nameObject instanceof RootObject) {
			s.add(allocator.getEnumDataTypes().getRoots(), -1, "Name", null); // 8
		} else if ((nameObject instanceof Integer) && ((int)nameObject == 0)) {
			s.add(allocator.getEnumDataTypes().getRoots(), -1, "Name", null); // 8
			nameObject = new RootObject("empty_string", "str");
		} else if ((nameObject instanceof Long) && ((long)nameObject == 0)) {
			s.add(allocator.getEnumDataTypes().getRoots(), -1, "Name", null); // 8
			nameObject = new RootObject("empty_string", "str");
		} else {
			s.add((new PointerDataType(CharDataType.dataType)), -1, "Name", null); // 8
		}
		
		final ReservObject scopeInfo1 = (ReservObject) obj.getAlignedObject(kScopeInfoOffset);
		scopeInfo1s = ScopeInfoStruct.fromReservObject(allocator, scopeInfo1);
		if (scopeInfo1s == null) {
			scopeInfo1s = new ScopeInfoStruct(scopeInfo1, allocator);
		}
		s.add(new PointerDataType(VoidDataType.dataType), -1, "ScopeInfo", null); // 12
		
		scopeInfo2s = obj.getAlignedObject(kOuterScopeInfoOffset);
		if (scopeInfo2s instanceof RootObject) {
			s.add(allocator.getEnumDataTypes().getRoots(), -1, "OuterScopeInfo", null); // 16
		} else {
			final ScopeInfoStruct scopeInfo2 = ScopeInfoStruct.fromReservObject(allocator, (ReservObject)scopeInfo2s);
			
			if (scopeInfo2 == null) {
				scopeInfo2s = new ScopeInfoStruct((ReservObject)scopeInfo2s, allocator);
			} else {
				scopeInfo2s = scopeInfo2;
			}
			s.add(new PointerDataType(VoidDataType.dataType), -1, "OuterScopeInfo", null); // 16
		}
		
		constructStub = (String) obj.getAlignedObject(kConstructStubOffset);
		s.add(allocator.getEnumDataTypes().getBuiltins(), -1, "ConstructStub", null); // 20
		
		instanceClass = (RootObject) obj.getAlignedObject(kInstanceClassNameOffset);
		s.add(allocator.getEnumDataTypes().getRoots(), -1, "InstanceClass", null); // 24
		
		final ReservObject bytecode_ = (ReservObject) obj.getAlignedObject(kFunctionDataOffset);
		bytecode = new BytecodeStruct(bytecode_, functionLiteralId, allocator);
		s.add(new PointerDataType(bytecode.toDataType()), -1, "Bytecode", null); // 28
		
		debugInfo = obj.getSmiInt(kDebugInfoOffset);
		s.add(DWordDataType.dataType, -1, "DebugInfo", null); // 36
		
		ident = obj.getAlignedObject(kFunctionIdentifierOffset); // string or empty_string
		if (ident instanceof RootObject) {
			s.add(allocator.getEnumDataTypes().getRoots(), -1, "Identifier", null);
		} else {
			s.add(new PointerDataType(CharDataType.dataType), -1, "Identifier", null); // 40
		}
		
		feedback = obj.getAlignedObject(kFeedbackMetadataOffset); // reserv
		if (feedback instanceof RootObject) {
			s.add(allocator.getEnumDataTypes().getRoots(), -1, "FeedbackMetadata", null);
		} else {
			feedback = new FeedbackMetadataStruct((ReservObject)feedback, functionLiteralId, allocator);
			
			s.add(((FeedbackMetadataStruct)feedback).toDataType(), -1, "FeedbackMetadata", null); // 44
		}
		
		preParsed = obj.getAlignedObject(kPreParsedScopeDataOffset); //root_object NullValue
		if (preParsed instanceof RootObject) {
			s.add(allocator.getEnumDataTypes().getRoots(), -1, "PreParsedScopeData", null);
		} else {
			s.add(new PointerDataType(VoidDataType.dataType), -1, "PreParsedScopeData", null); // 48
		}

		s.add(DWordDataType.dataType, -1, "FunctionLiteralId", null); // 52
		
		functionLength = obj.getInt(kLengthOffset);
		s.add(DWordDataType.dataType, -1, "FunctionLength", null); // 56
		
		formalParameterCount = obj.getInt(kFormalParameterCountOffset);
		s.add(DWordDataType.dataType, -1, "FormalParameterCount", null); // 60
		
		expectedNofProperties = obj.getInt(kExpectedNofPropertiesOffset);
		s.add(DWordDataType.dataType, -1, "ExpectedNofProperties", null); // 64
		
		startPositionAndType = obj.getInt(kStartPositionAndTypeOffset);
		s.add(DWordDataType.dataType, -1, "StartPositionAndType", null); // 68
		
		endPosition = obj.getInt(kEndPositionOffset);
		s.add(DWordDataType.dataType, -1, "EndPosition", null); // 72
		
		functionTokenPosition = obj.getInt(kFunctionTokenPositionOffset);
		s.add(DWordDataType.dataType, -1, "FunctionTokenPosition", null); // 76
		
		compilerHints = obj.getInt(kCompilerHintsOffset);
		s.add(DWordDataType.dataType, -1, "CompilerHints", null); // 80
		
		size = s.getLength();
	}
	
	public static SharedFunctionInfoStruct getSharedFunctionInfo(final ObjectsAllocator allocator, int funcIndex) {
		return allocator.getCreatedSharedFunc(funcIndex);
	}
	
	private static int getFunctionLiteralIdOffset(int pointerSize) {
		var kScriptOffset = getScriptOffset(pointerSize);
		var kDebugInfoOffset = kScriptOffset + pointerSize;
		var kFunctionIdentifierOffset = kDebugInfoOffset + pointerSize;
		var kFeedbackMetadataOffset = kFunctionIdentifierOffset + pointerSize;
		var kPreParsedScopeDataOffset = kFeedbackMetadataOffset + pointerSize;
		return kPreParsedScopeDataOffset + pointerSize;
	}
	
	public static int getScriptOffset(int pointerSize) {
		var kCodeOffset = ObjectsAllocator.kMetaMap + pointerSize;
		var kNameOffset = kCodeOffset + pointerSize;
		var kScopeInfoOffset = kNameOffset + pointerSize;
		var kOuterScopeInfoOffset = kScopeInfoOffset + pointerSize;
		var kConstructStubOffset = kOuterScopeInfoOffset + pointerSize;
		var kInstanceClassNameOffset = kConstructStubOffset + pointerSize;
		var kFunctionDataOffset = kInstanceClassNameOffset + pointerSize;
		return kFunctionDataOffset + pointerSize;
	}
	
	public static int getFunctionIndex(final ReservObject obj, int pointerSize) {
		 return obj.getInt(getFunctionLiteralIdOffset(pointerSize));
	}
	
	@Override
	public Address allocate(final ObjectsAllocator allocator, final TaskMonitor monitor) throws Exception {
		monitor.setMessage(String.format("Allocating %s...", this.getClass().getSimpleName()));
		
		// 4
		int typeIndex = (int) allocator.getEnumDataTypes().getBuiltins().getValue(codeOffset);
		Address result = sfAllocator.allocateNew(this, size);
		sfAllocator.allocate(typeIndex);
		
		// 8
		if (nameObject instanceof RootObject) {
			sfAllocator.allocate(nameObject);
		} else {
			sfAllocator.allocate(allocator.allocateInStrings(nameObject));
		}
		
		// 12
		sfAllocator.allocate(scopeInfo1s);
		
		// 16
		sfAllocator.allocate(scopeInfo2s);
		
		// 20
		typeIndex = (int) allocator.getEnumDataTypes().getBuiltins().getValue(constructStub);
		sfAllocator.allocate(typeIndex);
		
		// 24
		sfAllocator.allocate(instanceClass);
		
		sfAllocator.allocate(bytecode);
		Address bytecodeAddr = bytecode.getBaseAddress();
		
		sfAllocator.allocate(debugInfo);
		
		if (ident instanceof RootObject) {
			sfAllocator.allocate(ident);
		} else {
			sfAllocator.allocate(allocator.allocateInStrings(ident));
		}
		
		if (feedback instanceof RootObject) {
			sfAllocator.allocate(feedback);
		} else {
			sfAllocator.allocate((FeedbackMetadataStruct)feedback);
		}
		sfAllocator.allocate(preParsed);
		sfAllocator.allocate(functionLiteralId);
		sfAllocator.allocate(functionLength);
		sfAllocator.allocate(formalParameterCount);
		sfAllocator.allocate(expectedNofProperties);
		sfAllocator.allocate(startPositionAndType);
		sfAllocator.allocate(endPosition);
		sfAllocator.allocate(functionTokenPosition);
		sfAllocator.allocate(compilerHints);
		
		allocator.setDataStruct(result, this);
		
		initFunction(bytecodeAddr, scopeInfo1s, allocator);
		
		final SharedFunctionStore sfStore = SharedFunctionStore.fromStruct(this, allocator.getProgram());
		allocator.addToSharedFunctions(sfStore);
		
		return result;
	}
	
	private void initFunction(final Address funcAddr, final ScopeInfoStruct scopeInfo, final ObjectsAllocator allocator) throws Exception {
		if (nameObject instanceof RootObject) {
			name = ((RootObject) nameObject).getName();
		} else {
			name = (String) allocator.prepareForAlloc(nameObject);
		}
		
		name = name.replace(" ", "_").replace("empty_string", "");
		
		if (name.isEmpty()) {
			name = String.format("func_%04d", functionLiteralId);
		}
		
		allocator.getFpa().createLabel(funcAddr, name, true);
		Function func = allocator.getFpa().createFunction(funcAddr, name);

		func.setReturnType(IntegerDataType.dataType, SourceType.DEFAULT);
		
		List<ParameterImpl> args = new ArrayList<>();

		Program program = allocator.getFpa().getCurrentProgram();
		
		final List<String> params = scopeInfo.getParams();
		for (int i = params.size() - 1; i >= 0; --i) {
			final String param = params.get(i).replace("empty_string", "");
			args.add(new ParameterImpl(param, IntegerDataType.dataType, program.getRegister(String.format("a%d", i)), program, SourceType.USER_DEFINED));
		}
		args.add(new ParameterImpl("this", new PointerDataType(VoidDataType.dataType), program.getRegister(String.format("a%d", params.size() + 1)), program, SourceType.USER_DEFINED));
		func.updateFunction("__stdcall", null, FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS, true, SourceType.DEFAULT, args.toArray(ParameterImpl[]::new));
		
		final List<String> stackLocals = scopeInfo.getStackLocals();
		final List<String> addedStackLocals = new ArrayList<>();
		for (int i = 0; i < stackLocals.size(); ++i) {
			int stackOffset = scopeInfo.getStackLocalsFirstSlot() + i;
			String locName = stackLocals.get(i).replace("empty_string", "");
			
			if (!addedStackLocals.contains(locName)) {
				addedStackLocals.add(locName);
			} else if (!locName.isEmpty()) {
				locName = String.format("%s_%d", locName, i);
			}
			
			func.addLocalVariable(new LocalVariableImpl(locName, 0, IntegerDataType.dataType, program.getRegister(String.format("r%d", stackOffset)), program), SourceType.USER_DEFINED);
		}
	}
	
	public Object getName() {
		return name;
	}
	
	public Address getAddress() {
		return bytecode.getBaseAddress();
	}
	
	public ScopeInfoStruct getScopeInfo() {
		return scopeInfo1s;
	}
	
	public Object getOuterScope() {
		return scopeInfo2s;
	}
	
	public ConstantPoolStruct getConstantPool() {
		return bytecode.getConstantPool();
	}
	
	public HandlerTableStruct getHandlerTable() {
		return bytecode.getHandlerTable();
	}
	
	public int getSize() {
		return bytecode.getLength();
	}

	@Override
	public int hashCode() {
		return Objects.hash(functionLiteralId);
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj)
			return true;
		if (obj == null)
			return false;
		if (getClass() != obj.getClass())
			return false;
		SharedFunctionInfoStruct other = (SharedFunctionInfoStruct) obj;
		return functionLiteralId == other.functionLiteralId;
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		return s;
	}
}
