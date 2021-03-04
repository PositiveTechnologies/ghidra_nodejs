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
import v8_bytecode.allocator.BytecodesAllocator;
import v8_bytecode.allocator.IAllocatable;
import v8_bytecode.allocator.ObjectsAllocator;

public final class SourcePositionsStruct implements IAllocatable {

	private final ReservObject rObj;
	private final List<SourcePositionItemStruct> items;
	private final int count;
	
	private final Structure s;
	private BytecodesAllocator bcAllocator;
	private Address baseAddr;
	
	public SourcePositionsStruct(final ReservObject obj, int funcIndex, final ObjectsAllocator allocator) throws IOException, DuplicateNameException {
		rObj = obj;
		allocator.getMonitor().setMessage(String.format("Creating SourcePositions for function #%d", funcIndex));
		
		s = new StructureDataType(String.format("SourcePositions%d", funcIndex), 0);
		
		byte[] data = allocator.reservObjectToBytes(obj, 1, false);
		
		items = new ArrayList<>();
		
		int i = 0;
		int codeOff = 0;
		int srcOff = 0;
		
		while (i < data.length) {
			int[] tmp = new int[] {i};
			int a = getValue(data, tmp);
			i = tmp[0];
			
			int stat;
			
			if (a < 0) {
				stat = 0;
				a = -(1 + a);
				codeOff += a;
			} else {
				stat = 1;
				codeOff += a;
			}
			
			tmp = new int[] {i};
			int b = getValue(data, tmp);
			i = tmp[0];
			
			srcOff += b;
			
			SourcePositionItemStruct item = new SourcePositionItemStruct(stat, codeOff, srcOff, allocator);
			s.add(item.toDataType(), -1, String.format("Item%d", items.size()), null);
			items.add(item);
		}
		
		count = items.size();
	}
	
	private int getValue(final byte[] data, int[] pos) {
		int z = 0;
		int shift = 0;
		
		while (true) {
			int x = data[pos[0]];
			z |= (x & 0x7F) << shift;
			shift += 7;
			pos[0]++;
			
			if ((x & 0x80) == 0) {
				break;
			}
		}
		
		return zigzagDecode(z);
	}
	
	private int zigzagDecode(int value) {
		return (value >> 1) ^ ((-(value & 1)) & 0xFFFFFFFF);
	}
	
	public void setAllocator(final BytecodesAllocator bcAllocator) {
		this.bcAllocator = bcAllocator;
	}
	
	public void setBaseAddress(final Address baseAddr) {
		this.baseAddr = baseAddr;
	}
	
	@Override
	public Address allocate(final ObjectsAllocator allocator, final TaskMonitor monitor) throws Exception {
		monitor.setMessage(String.format("Allocating %s...", this.getClass().getSimpleName()));
		
		SourcePositionItemStruct item0 = items.get(0);
		Address result = bcAllocator.allocate(item0, baseAddr);
		
		for (int i = 1; i < count; ++i) {
			SourcePositionItemStruct item = items.get(i);
			bcAllocator.allocate(item, baseAddr);
		}
		
		return result;
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
		SourcePositionsStruct other = (SourcePositionsStruct) obj;
		return Objects.equals(rObj, other.rObj);
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		return s;
	}

}
