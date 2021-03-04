package v8_bytecode.allocator;

import ghidra.program.model.address.Address;

public final class TuplesAllocator implements IObjectAllocator {

	private final ObjectsAllocator base;
	private final AllocationInfoLast info;
	
	public TuplesAllocator(ObjectsAllocator base) {
		this.base = base;
		
		info = new AllocationInfoLast(base.getTuplesBlock());
	}
	
	@Override
	public Address allocateNew(IAllocatable obj, int size) throws Exception {
		Address result = info.getAllocAddress(base.getNewTupleAddress());
		base.incNewTupleAddress(size);
		base.addToAllocated(obj, result);
		return result;
	}

	@Override
	public Address allocate(Object data) throws Exception {
		return base.allocateData(info, data);
	}

}
