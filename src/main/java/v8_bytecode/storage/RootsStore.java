package v8_bytecode.storage;

import java.io.Serializable;
import java.util.List;

import v8_bytecode.RootObject;

public final class RootsStore implements Serializable {
	
	private final List<RootObject> roots;
	
	public RootsStore(final List<RootObject> roots) {
		this.roots = roots;
	}
	
	public List<RootObject> getRoots() {
		return roots;
	}

	public int fromString(final RootObject name) {
		return roots.indexOf(name);
	}
}
