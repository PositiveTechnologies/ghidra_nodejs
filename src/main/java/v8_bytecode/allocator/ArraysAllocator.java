package v8_bytecode.allocator;

import ghidra.program.model.address.Address;

public final class ArraysAllocator implements IObjectAllocator {
	
	private final ObjectsAllocator base;
	private final AllocationInfoLast info;
	
	public ArraysAllocator(final ObjectsAllocator base) throws Exception {
		this.base = base;
		
		info = new AllocationInfoLast(base.getArraysBlock());
	}
	
	@Override
	public Address allocateNew(final IAllocatable obj, int size) throws Exception {
		Address result = info.getAllocAddress(base.getNewArrayAddress());
		base.incNewArrayAddress(size);
		base.addToAllocated(obj, result);
		return result;
	}
	
	@Override
	public Address allocate(final Object data) throws Exception {
		return base.allocateData(info, data);
	}
}
