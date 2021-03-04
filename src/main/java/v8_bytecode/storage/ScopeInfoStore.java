package v8_bytecode.storage;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;

import v8_bytecode.RootObject;
import v8_bytecode.structs.ContextVarStruct;
import v8_bytecode.structs.ScopeInfoStruct;

public final class ScopeInfoStore implements Serializable {
	private final String name;
	private final long offset;
	private final List<ContextVarStore> ctxVars;
	private final ScopeInfoStore outerScope;
	
	private ScopeInfoStore(final String name, long offset, final List<ContextVarStore> ctxVars, final ScopeInfoStore outerScope) {
		this.name = name;
		this.offset = offset;
		this.ctxVars = ctxVars;
		this.outerScope = outerScope;
	}
	
	public static ScopeInfoStore fromStruct(final Object struct) {
		if (struct == null || struct instanceof RootObject) {
			return null;
		}
		
		final List<ContextVarStore> ctxVars1 = new ArrayList<>();
		
		for (final ContextVarStruct var : ((ScopeInfoStruct) struct).getContextVars()) {
			final ContextVarStore ctxVar;
			
			if (var == null) {
				ctxVar = null;
			} else {
				ctxVar = new ContextVarStore(var.getAddress().getOffset(), var.getName());
			}

			ctxVars1.add(ctxVar);
		}
		
		final ScopeInfoStore outerScope = ScopeInfoStore.fromStruct(((ScopeInfoStruct)struct).getOuterScope());
		return new ScopeInfoStore(((ScopeInfoStruct) struct).getName(), ((ScopeInfoStruct) struct).getAddress().getOffset(), ctxVars1, outerScope);
	}
	
	public String getName() {
		return name;
	}
	
	public long getOffset() {
		return offset;
	}
	
	public ContextVarStore getContextVar(int index) {
		if (index < ctxVars.size()) {
			return ctxVars.get(index);
		}
		
		if (outerScope == null) {
			return null;
		}
		
		return outerScope.getContextVar(index);
	}

	public ContextVarStore getContextVar(int index, int depth) {
		if (depth < 0) {
			depth = 0;
		}
		
		if (depth == 0 && index < ctxVars.size()) {
			return ctxVars.get(index);
		}
		
		return outerScope.getContextVar(index, depth - 1);
	}
}
