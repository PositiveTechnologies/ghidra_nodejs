package v8_bytecode.structs;

import java.io.IOException;
import java.util.Objects;

import ghidra.program.model.address.Address;
import ghidra.program.model.data.DWordDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.VoidDataType;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.task.TaskMonitor;
import v8_bytecode.HandlerTableEntry;
import v8_bytecode.allocator.BytecodesAllocator;
import v8_bytecode.allocator.IAllocatable;
import v8_bytecode.allocator.ObjectsAllocator;

public final class HandlerTableItemStruct implements IAllocatable {

	private final HandlerTableEntry entry;
	private Address baseAddr = null;
	
	private long startAddr = 0L;
	private long endAddr = 0L;
	private long offset = 0L;
	
	private final Structure s;
	private BytecodesAllocator bcAllocator;
	
	public HandlerTableItemStruct(final HandlerTableEntry entry, final ObjectsAllocator allocator) {
		this.entry = entry;
		
		allocator.getMonitor().setMessage("Creating HandlerTableItem");

		s = new StructureDataType("HTItem", 0);
		
		s.add(new PointerDataType(VoidDataType.dataType), -1, "Start", null);
		s.add(new PointerDataType(VoidDataType.dataType), -1, "End", null);
		s.add(allocator.getEnumDataTypes().getCatchPrediction(), -1, "Prediction", "Handler");
		s.add(new PointerDataType(VoidDataType.dataType), -1, "Offset", "Handler");
		s.add(DWordDataType.dataType, -1, "Data", null);
	}
	
	public void setBaseAddress(final Address addr) {
		baseAddr = addr;
	}
	
	public void setAllocator(final BytecodesAllocator bcAllocator) {
		this.bcAllocator = bcAllocator;
	}
	
	@Override
	public Address allocate(final ObjectsAllocator allocator, final TaskMonitor monitor) throws Exception {
		monitor.setMessage(String.format("Allocating %s...", this.getClass().getSimpleName()));
		
		startAddr = entry.getStart();
		Address result = bcAllocator.allocate(baseAddr.add(startAddr));
		
		endAddr = entry.getEnd();
		bcAllocator.allocate(baseAddr.add(endAddr));
		
		bcAllocator.allocate(entry.getPrediction());
		
		offset = entry.getHandlerOffset();
		bcAllocator.allocate(baseAddr.add(offset));
		
		bcAllocator.allocate(entry.getData());
		
		return result;
	}
	
	public long getStartAddress() {
		return startAddr;
	}
	
	public long getEndAddress() {
		return endAddr;
	}
	
	public long getOffset() {
		return offset;
	}

	@Override
	public int hashCode() {
		return Objects.hash(entry);
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj)
			return true;
		if (obj == null)
			return false;
		if (getClass() != obj.getClass())
			return false;
		HandlerTableItemStruct other = (HandlerTableItemStruct) obj;
		return Objects.equals(entry, other.entry);
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		return s;
	}

}
