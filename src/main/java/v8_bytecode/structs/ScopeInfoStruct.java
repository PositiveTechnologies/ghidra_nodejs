package v8_bytecode.structs;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;

import ghidra.program.model.address.Address;
import ghidra.program.model.data.CharDataType;
import ghidra.program.model.data.DWordDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.VoidDataType;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.task.TaskMonitor;
import v8_bytecode.ReservObject;
import v8_bytecode.RootObject;
import v8_bytecode.ScopeInfoFlags;
import v8_bytecode.allocator.IAllocatable;
import v8_bytecode.allocator.ObjectsAllocator;
import v8_bytecode.allocator.ScopesInfoAllocator;

public final class ScopeInfoStruct implements IAllocatable {
	private final Structure s;

	private final int index;
	private final int flags;
	private final int paramsCount;
	private final List<String> params;
	private final int stackLocalsCount;
	private final int stackLocalsFirstSlot;
	private final List<Object> stackLocals;
	private final List<String> stackLocalsStr;
	private final int contextLocalsCount;
	private final List<ContextVarStruct> contextLocals;
	private final ScopeInfoReceiver receiver;
	private final ScopeInfoReceiver funcVar;
	private ScopeInfoStruct outerScope;
	
	private final String name;
	
	private final ReservObject rObj;
	private final int size;
	private final ScopesInfoAllocator siAllocator;
	
	private Address allocAddr = null;
	
	public static long kFlagsOffset;
	public static long kParameterCount;
	public static long kStackLocalCount;
	public static long kContextLocalCount;
	
	public static long kParamsOffset;

	public ScopeInfoStruct(final ReservObject obj, final ObjectsAllocator allocator) throws Exception {
		int pointerSize = allocator.getPointerSize();
		
		// start offsets initializing
		kFlagsOffset = pointerSize + pointerSize;
		kParameterCount = kFlagsOffset + pointerSize;
		kStackLocalCount = kParameterCount + pointerSize;
		kContextLocalCount = kStackLocalCount + pointerSize;
		kParamsOffset = kContextLocalCount + pointerSize;
		// end offsets initializing
		
		rObj = obj;
		siAllocator = new ScopesInfoAllocator(allocator);
		
		index = allocator.getCreatedScopesSize();
		allocator.addToCreatedScopes(obj, this);
		
		allocator.getMonitor().setMessage(String.format("Creating ScopeInfo #%d", index));
		
		name = String.format("ScopeInfo%d", index);
		s = new StructureDataType(name, 0);

		flags = obj.getSmiInt(kFlagsOffset);
		s.add(DWordDataType.dataType, -1, "Flags", null); // 8
		
		ScopeInfoFlags scopeFlags = new ScopeInfoFlags(flags);
		
		paramsCount = obj.getSmiInt(kParameterCount);
		s.add(DWordDataType.dataType, -1, "ParamsCount", null); // 12
		
		stackLocalsCount = obj.getSmiInt(kStackLocalCount);
		s.add(DWordDataType.dataType, -1, "StackLocalsCount", null); // 16
		
		contextLocalsCount = obj.getSmiInt(kContextLocalCount);
		s.add(DWordDataType.dataType, -1, "ContextLocalsCount", null); // 20
		
		long offset = kParamsOffset;
		
		params = new ArrayList<>();
		if (paramsCount > 0) {
			for (int i = 0; i < paramsCount; ++i) {
				s.add(new PointerDataType(CharDataType.dataType), -1, String.format("Param%d", i + 1), null);
				final Object param = obj.getAlignedObject(offset);
				
				if (param instanceof RootObject) {
					params.add(((RootObject)param).getName());
				} else {
					params.add((String)allocator.prepareForAlloc(param));
				}
				
				offset += pointerSize;
			}
		}
		
		stackLocalsFirstSlot = obj.getSmiInt(offset);
		s.add(DWordDataType.dataType, -1, "StackLocalsFirstSlot", null);
		offset += pointerSize;
		
		stackLocals = new ArrayList<>();
		stackLocalsStr = new ArrayList<>();
		if (stackLocalsCount > 0) {
			for (int i = 0; i < stackLocalsCount; ++i) {
				final Object stackObj = obj.getAlignedObject(offset);
				stackLocals.add(stackObj);
				
				if (stackObj instanceof RootObject)	{
					s.add(allocator.getEnumDataTypes().getRoots(), -1, String.format("StackLocal%d", i + 1), null);
					stackLocalsStr.add(((RootObject)stackObj).getName());
				} else {
					s.add(new PointerDataType(CharDataType.dataType), -1, String.format("StackLocal%d", i + 1), null);
					stackLocalsStr.add((String)allocator.prepareForAlloc(stackObj));
				}
				
				offset += pointerSize;
			}
		}
		
		contextLocals = new ArrayList<>();
		contextLocals.addAll(Arrays.asList(null, null, null, null));
		if (contextLocalsCount > 0) {
			for (int i = 0; i < contextLocalsCount; ++i) {
				long varInfoOff = contextLocalsCount * pointerSize + offset;
				int varInfo = obj.getSmiInt(varInfoOff);
				
				final Object ctxLocal = obj.getAlignedObject(offset);
				
				String _name;
				if (ctxLocal instanceof RootObject) {
					_name = ((RootObject)ctxLocal).getName();
				} else {
					_name = (String) allocator.convertReservObject((ReservObject)ctxLocal);
				}
				ContextVarStruct var = new ContextVarStruct(varInfo, _name, allocator);
				s.add(var.toDataType(), -1, String.format("ContextLocal%d", i + 1), null);
				contextLocals.add(var);
				offset += pointerSize;
			}
			
			offset += contextLocalsCount * pointerSize;
		}
		
		if (scopeFlags.hasReceiver()) {
			receiver = new ScopeInfoReceiver(obj.getInt(offset), null, "Recv", index, allocator);
			s.add(receiver.toDataType(), -1, "Receiver", null);
			offset += pointerSize;
		} else {
			receiver = null;
		}
		
		if (scopeFlags.hasFunctionVar()) {
			funcVar = new ScopeInfoReceiver(obj.getInt(offset), (String)obj.getAlignedObject(offset + pointerSize), "Var", index, allocator);
			s.add(funcVar.toDataType(), -1, "FuncVar", null);
			offset += pointerSize;
		} else {
			funcVar = null;
		}
		
		if (scopeFlags.hasOuterScopeInfo()) {
			final Object outerScope_ = obj.getAlignedObject(offset);
			
			outerScope = fromReservObject(allocator, (ReservObject) outerScope_);
			
			if (outerScope == null) {
				outerScope = new ScopeInfoStruct((ReservObject)outerScope_, allocator);
			}
			s.add(new PointerDataType(VoidDataType.dataType), -1, "OuterScope", null);
			offset += pointerSize;
		} else {
			outerScope = null;
		}
		
		size = s.getLength();
	}
	
	public static ScopeInfoStruct fromReservObject(final ObjectsAllocator allocator, final ReservObject obj) {
		return allocator.getScopeInfoByObject(obj);
	}
	
	public List<String> getParams() {
		return params;
	}
	
	public List<String> getStackLocals() {
		return stackLocalsStr;
	}
	
	public int getStackLocalsFirstSlot() {
		return stackLocalsFirstSlot;
	}
	
	public List<ContextVarStruct> getContextVars() {
		return contextLocals;
	}
	
	@Override
	public Address allocate(final ObjectsAllocator allocator, final TaskMonitor monitor) throws Exception {
		monitor.setMessage(String.format("Allocating %s...", this.getClass().getSimpleName()));
		
		// 4
		Address result = allocAddr = siAllocator.allocateNew(this, size);
		siAllocator.allocate(flags);
		
		siAllocator.allocate(paramsCount);
		siAllocator.allocate(stackLocalsCount);
		siAllocator.allocate(contextLocalsCount);

		for (int i = 0; i < paramsCount; ++i) {
			final Object paramObj = params.get(i);
			
			siAllocator.allocate(allocator.allocateInStrings(paramObj));
		}
		
		siAllocator.allocate(stackLocalsFirstSlot);
		
		for (int i = 0; i < stackLocalsCount; ++i) {
			final Object stackLocal = stackLocals.get(i);
			
			if (stackLocal instanceof RootObject) {
				siAllocator.allocate(stackLocal);
			} else {
				siAllocator.allocate(allocator.allocateInStrings(stackLocal));
			}
		}
		
		for (int i = 4; i < contextLocals.size(); ++i) {
			siAllocator.allocate(contextLocals.get(i));
		}
		
		if (receiver != null) {
			siAllocator.allocate(receiver);
		}
		
		if (funcVar != null) {
			siAllocator.allocate(funcVar);
		}
		
		if (outerScope != null) {
			siAllocator.allocate(outerScope);
		}
		
		allocator.setDataStruct(result, this);

		return result;
	}
	
	public Address getAddress() {
		return allocAddr;
	}
	
	public String getName() {
		return name;
	}
	
	public ScopeInfoStruct getOuterScope() {
		return outerScope;
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
		ScopeInfoStruct other = (ScopeInfoStruct) obj;
		return Objects.equals(this.rObj, other.rObj);
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		return s;
	}
}
