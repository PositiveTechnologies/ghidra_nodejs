package v8_bytecode.enums;

import ghidra.program.model.data.EnumDataType;
import v8_bytecode.RootObject;
import v8_bytecode.storage.RootsStore;

public final class RootsEnum extends EnumDataType {
	public static final String NAME = "ROOTS";
	
	public RootsEnum(final RootsStore store) {
		super(NAME, 4);
		
		for (final RootObject root : store.getRoots()) {
			try {
				add(root.getName(), this.getCount());
			} catch (IllegalArgumentException e) {
				add(root.getName() + "1", this.getCount());
			}
		}
	}
}
