package v8_bytecode.structs;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.task.TaskMonitor;
import v8_bytecode.HandlerTableEntry;
import v8_bytecode.ReservObject;
import v8_bytecode.allocator.BytecodesAllocator;
import v8_bytecode.allocator.IAllocatable;
import v8_bytecode.allocator.ObjectsAllocator;

public final class HandlerTableStruct implements IAllocatable {

	private final Structure s;
	
	private final ReservObject rObj;
	private Address baseAddr = null;
	private final int count;
	private final List<HandlerTableItemStruct> items;

	private BytecodesAllocator bcAllocator;
	
	public HandlerTableStruct(final ReservObject obj, int funcIndex, final ObjectsAllocator allocator) throws DuplicateNameException, IOException {
		int pointerSize = allocator.getPointerSize();
		
		rObj = obj;
		allocator.getMonitor().setMessage(String.format("Creating HandlerTable for function #%d", funcIndex));
		
		s = new StructureDataType(String.format("HandlerTable%d", funcIndex), 0);

		count = obj.getSmiInt(ArrayStruct.getArrayLengthOffset(pointerSize)) / 4;
		
		items = new ArrayList<>();
		
		for (int i = 0; i < count; ++i) {
			int start = obj.getSmiInt(  ArrayStruct.getArrayHeaderSize(pointerSize) + (4 * i + 0) * pointerSize);
			int end = obj.getSmiInt(    ArrayStruct.getArrayHeaderSize(pointerSize) + (4 * i + 1) * pointerSize);
			int handler = obj.getSmiInt(ArrayStruct.getArrayHeaderSize(pointerSize) + (4 * i + 2) * pointerSize);
			int data = obj.getSmiInt(   ArrayStruct.getArrayHeaderSize(pointerSize) + (4 * i + 3) * pointerSize);
			
			HandlerTableEntry entry = new HandlerTableEntry(start, end, handler & 7, handler >> 3, data);
			HandlerTableItemStruct hti = new HandlerTableItemStruct(entry, allocator);
			items.add(hti);
			
			s.add(hti.toDataType(), -1, String.format("Item%d", i), null);
		}
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
		
		// 8
		Address result = bcAllocator.allocate(items.get(0), baseAddr);

		for (int i = 1; i < count; ++i) {
			bcAllocator.allocate(items.get(i), baseAddr);
		}
		
		return result;
	}
	
	public List<HandlerTableItemStruct> getItems() {
		return items;
	}

	@Override
	public int hashCode() {
		return Objects.hash(rObj);
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj)
			return true;
		if (obj == null)
			return false;
		if (getClass() != obj.getClass())
			return false;
		HandlerTableStruct other = (HandlerTableStruct) obj;
		return Objects.equals(rObj, other.rObj);
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		return s;
	}

}
