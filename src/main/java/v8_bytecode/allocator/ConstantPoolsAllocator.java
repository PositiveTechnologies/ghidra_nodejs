package v8_bytecode.allocator;

import ghidra.program.model.address.Address;

public final class ConstantPoolsAllocator implements IObjectAllocator {
	
	private final ObjectsAllocator base;
	private final AllocationInfoLast info;
	
	public ConstantPoolsAllocator(final ObjectsAllocator base) throws Exception {
		this.base = base;
		
		info = new AllocationInfoLast(base.getConstantPoolsBlock());
	}
	
	@Override
	public Address allocateNew(final IAllocatable obj, int size) throws Exception {
		Address result = info.getAllocAddress(base.getNewConstantPoolAddress());
		base.incNewConstantPoolAddress(size);
		base.addToAllocated(obj, result);
		return result;
	}
	
	@Override
	public Address allocate(final Object data) throws Exception {
		return base.allocateData(info, data);
	}
}
