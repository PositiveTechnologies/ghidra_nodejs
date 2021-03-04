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
import v8_bytecode.ReservObject;
import v8_bytecode.allocator.IAllocatable;
import v8_bytecode.allocator.ObjectsAllocator;
import v8_bytecode.allocator.TuplesAllocator;

public final class TupleStruct implements IAllocatable {

	private final Structure s;
	
	private final ReservObject rObj;
	private final int count;
	private final List<Object> items;
	
	private final String name;
	private final int size;
	private final TuplesAllocator tpAllocator;
	
	public TupleStruct(final ReservObject obj, int count, final ObjectsAllocator allocator) throws Exception {
		rObj = obj;
		tpAllocator = new TuplesAllocator(allocator);
		
		this.count = count;
		int index = allocator.getCreatedTuplesSize();
		allocator.addToCreatedTuples(obj);
		
		allocator.getMonitor().setMessage(String.format("Creating Tuple%d #%d", count, index));
		
		name = String.format("Tuple%d_N%d", count, index);
		s = new StructureDataType(name, 0);
		
		items = new ArrayList<>();
		
		int kPointerSize = allocator.getPointerSize();
		
		for (int i = 0; i < count; ++i) {
			final Object item = allocator.prepareForAlloc(obj.getAlignedObject((1 + i) * kPointerSize));
			items.add(item);
			
			allocator.addStructureField(s, item, String.format("Item%d", i));
		}
		
		size = s.getLength();
	}
	
	@Override
	public Address allocate(final ObjectsAllocator allocator, final TaskMonitor monitor) throws Exception {
		monitor.setMessage(String.format("Allocating %s...", this.getClass().getSimpleName()));
		
		Address result = tpAllocator.allocateNew(this, size);
		tpAllocator.allocate(items.get(0));
		
		for (int i = 1; i < count; ++i) {
			final Object item = items.get(i);
			
			if (item instanceof String) {
				tpAllocator.allocate(allocator.allocateInStrings(item));
			} else {
				tpAllocator.allocate(item);
			}
		}
		
		allocator.setDataStruct(result, this);
		
		return result;
	}
	
	public String getName() {
		return name;
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
		TupleStruct other = (TupleStruct) obj;
		return Objects.equals(rObj, other.rObj);
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		return s;
	}
}
