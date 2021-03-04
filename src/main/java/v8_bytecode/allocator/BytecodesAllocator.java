package v8_bytecode.allocator;

import ghidra.program.model.address.Address;
import v8_bytecode.structs.HandlerTableItemStruct;
import v8_bytecode.structs.HandlerTableStruct;
import v8_bytecode.structs.SourcePositionItemStruct;
import v8_bytecode.structs.SourcePositionsStruct;

public final class BytecodesAllocator implements IObjectAllocator {

	private final ObjectsAllocator base;
	private final AllocationInfoLast info;
	
	public BytecodesAllocator(ObjectsAllocator base) {
		this.base = base;
		
		info = new AllocationInfoLast(base.getBytecodesInfoBlock());
	}
	
	@Override
	public Address allocateNew(IAllocatable obj, int size) throws Exception {
		Address result = info.getAllocAddress(base.getNewBytecodeInfoAddress());
		base.incNewBytecodeInfoAddress(size);
		base.addToAllocated(obj, result);
		return result;
	}

	@Override
	public Address allocate(final Object data) throws Exception {
		return base.allocateData(info, data);
	}
	
	public Address allocate(final SourcePositionItemStruct spti, final Address baseAddr) throws Exception {
		spti.setAllocator(this);
		spti.setBaseAddress(baseAddr);
		return spti.allocate(base, base.getMonitor());
	}
	
	public Address allocate(final SourcePositionsStruct spt, final Address baseAddr) throws Exception {
		spt.setAllocator(this);
		spt.setBaseAddress(baseAddr);
		return spt.allocate(base, base.getMonitor());
	}
	
	public Address allocate(final HandlerTableItemStruct hti, final Address baseAddr) throws Exception {
		hti.setAllocator(this);
		hti.setBaseAddress(baseAddr);
		return hti.allocate(base, base.getMonitor());
	}
	
	public Address allocate(final HandlerTableStruct ht, final Address baseAddr) throws Exception {
		ht.setAllocator(this);
		ht.setBaseAddress(baseAddr);
		return ht.allocate(base, base.getMonitor());
	}
}
