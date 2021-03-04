package v8_bytecode.structs;

import java.io.IOException;

import ghidra.program.model.address.Address;
import ghidra.program.model.data.DWordDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.task.TaskMonitor;
import v8_bytecode.allocator.BytecodesAllocator;
import v8_bytecode.allocator.IAllocatable;
import v8_bytecode.allocator.ObjectsAllocator;

public final class SourcePositionItemStruct implements IAllocatable {

	private final Structure s;
	
	private Address baseAddr = null;
	
	private final int stat;
	private final int codeOff;
	private final int srcOff;

	private BytecodesAllocator bcAllocator = null;
	
	public SourcePositionItemStruct(int stat, int codeOff, int srcOff, final ObjectsAllocator allocator) {
		s = new StructureDataType("SourcePosition", 0);
		
		this.stat = stat;
		s.add(allocator.getEnumDataTypes().getSpt(), -1, "Type", null);
		
		this.codeOff = codeOff;
		s.add(PointerDataType.dataType, -1, "CodeOffset", null);
		
		this.srcOff = srcOff;
		s.add(DWordDataType.dataType, -1, "SourcePos", null);
	}
	
	public void setBaseAddress(final Address baseAddr) {
		this.baseAddr = baseAddr;
	}
	
	public void setAllocator(final BytecodesAllocator bcAllocator) {
		this.bcAllocator  = bcAllocator;
	}
	
	@Override
	public Address allocate(final ObjectsAllocator allocator, final TaskMonitor monitor) throws Exception {
		monitor.setMessage(String.format("Allocating %s...", this.getClass().getSimpleName()));
		
		Address result = bcAllocator.allocate(stat);
		
		bcAllocator.allocate(baseAddr.add(codeOff));
		bcAllocator.allocate(srcOff);
		
		return result;
	}
	
	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		return s;
	}
}
