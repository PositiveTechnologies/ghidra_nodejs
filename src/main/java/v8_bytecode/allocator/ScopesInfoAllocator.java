package v8_bytecode.allocator;

import ghidra.program.model.address.Address;
import v8_bytecode.structs.ContextVarStruct;
import v8_bytecode.structs.ScopeInfoReceiver;

public final class ScopesInfoAllocator implements IObjectAllocator {
	
	private final ObjectsAllocator base;
	private final AllocationInfoLast info;
	
	public ScopesInfoAllocator(final ObjectsAllocator base) {
		this.base = base;
		
		info = new AllocationInfoLast(base.getScopesInfoBlock());
	}
	
	@Override
	public Address allocateNew(IAllocatable obj, int size) throws Exception {
		Address result = info.getAllocAddress(base.getNewScopeInfoAddress());
		base.incNewScopeInfoAddress(size);
		base.addToAllocated(obj, result);
		return result;
	}

	@Override
	public Address allocate(Object data) throws Exception {
		return base.allocateData(info, data);
	}
	
	public Address allocate(ContextVarStruct cv) throws Exception {
		cv.setAllocator(this);
		return cv.allocate(base, base.getMonitor());
	}
	
	public Address allocate(ScopeInfoReceiver sir) throws Exception {
		sir.setAllocator(this);
		return sir.allocate(base, base.getMonitor());
	}

}
