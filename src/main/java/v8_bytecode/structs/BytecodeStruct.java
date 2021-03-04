package v8_bytecode.structs;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Arrays;
import java.util.Objects;

import ghidra.program.model.address.Address;
import ghidra.program.model.data.ByteDataType;
import ghidra.program.model.data.DWordDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.VoidDataType;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.task.TaskMonitor;
import v8_bytecode.ReservObject;
import v8_bytecode.RootObject;
import v8_bytecode.allocator.BytecodesAllocator;
import v8_bytecode.allocator.IAllocatable;
import v8_bytecode.allocator.ObjectsAllocator;

public final class BytecodeStruct implements IAllocatable {
	private final int length;
	private Object cp;
	private Object ht;
	private final SourcePositionsStruct spt;
	
	private final int funcIndex;
	private final int frameSize;
	private final int parameterSize;
	private final int incoming;
	private final int interruptBudget;
	private final byte osrNestingLevel;
	private final byte bytecodeAge;
	
	private final byte[] bytecode;
	private final Structure s;
	
	private final int size;
	private final BytecodesAllocator bcAllocator;
	
	private Address baseAddr = null;

	public final int kConstantPoolOffset;
	public final int kHandlerTableOffset;
	public final int kSourcePositionTableOffset;
	public final int kFrameSizeOffset;
	public final int kParameterSizeOffset;
	public final int kIncomingNewTargetOrGeneratorRegisterOffset;
	public final int kInterruptBudgetOffset;
	public final int kOSRNestingLevelOffset;
	public final int kBytecodeAgeOffset;
	public final int kHeaderSize;
	
	public BytecodeStruct(final ReservObject obj, int funcIndex, final ObjectsAllocator allocator) throws Exception {
		int pointerSize = allocator.getPointerSize();
		
		// start offsets initializing
		kConstantPoolOffset = ArrayStruct.getArrayHeaderSize(pointerSize);
		kHandlerTableOffset = kConstantPoolOffset + pointerSize;
		kSourcePositionTableOffset = kHandlerTableOffset + pointerSize;
		kFrameSizeOffset = kSourcePositionTableOffset + pointerSize;
		kParameterSizeOffset = kFrameSizeOffset + 4;
		kIncomingNewTargetOrGeneratorRegisterOffset = kParameterSizeOffset + 4;
		kInterruptBudgetOffset = kIncomingNewTargetOrGeneratorRegisterOffset + 4;
		kOSRNestingLevelOffset = kInterruptBudgetOffset + 4;
		kBytecodeAgeOffset = kOSRNestingLevelOffset + 1;
		kHeaderSize = kBytecodeAgeOffset + 1 + 2;
		// end offsets initializing
		
		bcAllocator = new BytecodesAllocator(allocator);
		
		this.funcIndex = funcIndex;
		
		allocator.getMonitor().setMessage(String.format("Creating bytecode for function #%d", funcIndex));
		
		s = new StructureDataType(String.format("Bytecode%d", funcIndex), 0);

		// 4
		length = obj.getSmiInt(ArrayStruct.getArrayLengthOffset(pointerSize));
		s.add(DWordDataType.dataType, -1, "Length", null);
		
		cp = obj.getAlignedObject(kConstantPoolOffset);
		if (cp instanceof RootObject) {
			s.add(allocator.getEnumDataTypes().getRoots(), -1, "ConstantPool", null);
		} else {
			cp = new ConstantPoolStruct((ReservObject)cp, funcIndex, allocator);
			s.add(new PointerDataType(VoidDataType.dataType), -1, "ConstantPool", null);
		}
		
		// 12
		ht = obj.getAlignedObject(kHandlerTableOffset);
		
		if (ht instanceof RootObject) {
			s.add(allocator.getEnumDataTypes().getRoots(), -1, "HandlerTable", null);
		} else {
			ht = new HandlerTableStruct((ReservObject)ht, funcIndex, allocator);
			s.add(((HandlerTableStruct)ht).toDataType(), -1, "HandlerTable", null);
		}
		
		// 16
		final Object sptObj = obj.getAlignedObject(kSourcePositionTableOffset);
		spt = new SourcePositionsStruct((ReservObject)sptObj, funcIndex, allocator);
		s.add(spt.toDataType(), -1, "SourcePositions", null);
		
		// 20
		frameSize = obj.getInt(kFrameSizeOffset);
		s.add(DWordDataType.dataType, -1, "FrameSize", null);
		
		// 24
		parameterSize = obj.getInt(kParameterSizeOffset) / pointerSize;
		s.add(DWordDataType.dataType, -1, "ParameterSize", null);
		
		// 28
		incoming = obj.getInt(kIncomingNewTargetOrGeneratorRegisterOffset);
		s.add(DWordDataType.dataType, -1, "Incoming", null);
		
		// 32
		interruptBudget = obj.getInt(kInterruptBudgetOffset);
		s.add(DWordDataType.dataType, -1,"InterruptBudget", null);
		
		// 36
		// convert from dwords to bytes
		int tmp = obj.getInt(kOSRNestingLevelOffset);
		osrNestingLevel = (byte)((tmp >> 0) & 0xFF);
		s.add(ByteDataType.dataType, 1, "OSRNestingLevel", null);
		
		// 37
		bytecodeAge = (byte)((tmp >> 8) & 0xFF);
		s.add(ByteDataType.dataType, 1, "BytecodeAge", null);
		
		ByteArrayOutputStream out = new ByteArrayOutputStream(length);
		
		// 38
		out.write((byte)((tmp >> 16) & 0xFF));
		out.write((byte)((tmp >> 24) & 0xFF));
		for (int i = 0; i < (length - 2); i += 4) {
			byte[] bb = ObjectsAllocator.intToBytes(obj.getInt(kHeaderSize + i));
			out.write(bb);
		}
		bytecode = Arrays.copyOf(out.toByteArray(), length);
		
		s.add(new PointerDataType(ByteDataType.dataType), -1, "BytecodeData", null);
		
		size = s.getLength();
	}
	
	@Override
	public Address allocate(final ObjectsAllocator allocator, final TaskMonitor monitor) throws Exception {
		monitor.setMessage(String.format("Allocating %s...", this.getClass().getSimpleName()));
		
		// 4
		Address result = bcAllocator.allocateNew(this, size);
		bcAllocator.allocate(length);

		// 8
		bcAllocator.allocate(cp);
		
		baseAddr = allocator.allocateInCode(bytecode);
		
		// 12
		if (ht instanceof RootObject) {
			bcAllocator.allocate(ht);
		} else {
			bcAllocator.allocate((HandlerTableStruct)ht, baseAddr);
		}
		
		// 16
		bcAllocator.allocate(spt, baseAddr);
		
		bcAllocator.allocate(frameSize);
		bcAllocator.allocate(parameterSize);
		bcAllocator.allocate(incoming);
		bcAllocator.allocate(interruptBudget);
		
		bcAllocator.allocate(osrNestingLevel);
		bcAllocator.allocate(bytecodeAge);
		
		bcAllocator.allocate(baseAddr);
		
		allocator.setDataStruct(result, this);
		
		return result;
	}
	
	public Address getBaseAddress() {
		return baseAddr;
	}
	
	public int getLength() {
		return length;
	}
	
	public ConstantPoolStruct getConstantPool() {
		if (cp instanceof ConstantPoolStruct) {
			return (ConstantPoolStruct) cp;
		}
		
		return null;
	}
	
	public HandlerTableStruct getHandlerTable() {
		if (ht instanceof HandlerTableStruct) {
			return (HandlerTableStruct) ht;
		}
		
		return null;
	}

	@Override
	public int hashCode() {
		return Objects.hash(funcIndex);
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj)
			return true;
		if (obj == null)
			return false;
		if (getClass() != obj.getClass())
			return false;
		BytecodeStruct other = (BytecodeStruct) obj;
		return funcIndex == other.funcIndex;
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		return s;
	}
}
