package v8_bytecode.allocator;

import ghidra.program.model.address.Address;
import v8_bytecode.structs.FeedbackMetadataStruct;

public final class SharedFunctionsAllocator implements IObjectAllocator {
	
	private final ObjectsAllocator base;
	private final AllocationInfoLast info;
	
	public SharedFunctionsAllocator(final ObjectsAllocator base) {
		this.base = base;
		
		info = new AllocationInfoLast(base.getSharedFunctionsInfoBlock());
	}
	
	@Override
	public Address allocateNew(IAllocatable obj, int size) throws Exception {
		Address result = info.getAllocAddress(base.getNewSharedFunctionInfoAddress());
		base.incNewSharedFunctionInfoAddress(size);
		base.addToAllocated(obj, result);
		return result;
	}

	@Override
	public Address allocate(Object data) throws Exception {
		return base.allocateData(info, data);
	}

	public Address allocate(FeedbackMetadataStruct metadata) throws Exception {
		metadata.setAllocator(this);
		return metadata.allocate(base, base.getMonitor());
	}
}
