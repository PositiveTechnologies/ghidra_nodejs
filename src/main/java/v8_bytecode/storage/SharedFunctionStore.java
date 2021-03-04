package v8_bytecode.storage;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import generic.stl.Pair;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import v8_bytecode.RootObject;
import v8_bytecode.structs.ArrayStruct;
import v8_bytecode.structs.ConstantPoolStruct;
import v8_bytecode.structs.ScopeInfoStruct;
import v8_bytecode.structs.SharedFunctionInfoStruct;
import v8_bytecode.structs.TupleStruct;

public final class SharedFunctionStore implements Serializable {
	private final String name;
	private final long offset;
	private final int size;
	private final ScopeInfoStore outerScope;
	private final ConstantPoolStore cp;
	
	private final Map<String, ScopeInfoStore> scopes;
	
	private SharedFunctionStore(final String name, long offset, int size, final ScopeInfoStore scopeInfo, final ScopeInfoStore outerScope, final ConstantPoolStore cp, final Program program) {
		this.name = name;
		this.offset = offset;
		this.size = size;
		
		scopes = new HashMap<>();
		scopes.put("_context", scopeInfo);
		
		this.outerScope = outerScope;
		this.cp = cp;
	}
	
	public static SharedFunctionStore fromStruct(final SharedFunctionInfoStruct struct, final Program program) {
		final ScopeInfoStruct scopeInfo1s = struct.getScopeInfo();
		final Object scopeInfo2s = struct.getOuterScope();
		
		final ScopeInfoStore siStore = ScopeInfoStore.fromStruct(scopeInfo1s);
		final ScopeInfoStore osiStore = ScopeInfoStore.fromStruct(scopeInfo2s);
		
		final ConstantPoolStruct cpStruct = struct.getConstantPool();
		final ConstantPoolStore cp;
		if (cpStruct != null) {
			final List<Pair<Object, Address>> cpItems = cpStruct.getItems();
			
			final List<ConstantPoolItemStore> items = new ArrayList<>();
			for (final Pair<Object, Address> item : cpItems) {
				Object obj = null;
				
				if (item.first instanceof SharedFunctionInfoStruct) {
					final SharedFunctionInfoStruct sfObj = (SharedFunctionInfoStruct)item.first;
					obj = fromStruct(sfObj, program);
				} else if (item.first instanceof ScopeInfoStruct) {
					obj = ScopeInfoStore.fromStruct(item.first);
				} else if (item.first instanceof ArrayStruct) {
					obj = ArrayStore.fromStruct((ArrayStruct) item.first);
				} else if (item.first instanceof TupleStruct) {
					obj = TupleStore.fromStruct((TupleStruct) item.first);
				} else if (item.first instanceof String ||
						item.first instanceof Integer ||
						item.first instanceof Long ||
						item.first instanceof Double ||
						item.first instanceof RootObject) {
					obj = item.first;
				} else {
					//System.out.println(item.first);
				}
				
				final ConstantPoolItemStore cpItem = new ConstantPoolItemStore(obj, item.second.getOffset());
				items.add(cpItem);
			}
			
			cp = new ConstantPoolStore(items);
		} else {
			cp = null;
		}
		
		return new SharedFunctionStore((String)struct.getName(), struct.getAddress().getOffset(), struct.getSize(), siStore, osiStore, cp, program);
	}

	public String getName() {
		return name;
	}

	public long getAddress() {
		return offset;
	}
	
	public boolean contains(long addr) {
		return (addr >= offset) && (addr < (offset + size)); 
	}

	public ScopeInfoStore getScopeInfo(final String reg) {
		return scopes.get(reg);
	}
	
	public ScopeInfoStore getOuterScopeInfo() {
		return outerScope;
	}
	
	public void pushScopeInfo(final String reg, final ScopeInfoStore scope) {
		scopes.put(reg, scope);
	}

	public ScopeInfoStore popScopeInfo(final String reg) {
		return scopes.remove(reg);
	}

	public ConstantPoolStore getConstantPool() {
		return cp;
	}
}
