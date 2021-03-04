package v8_bytecode.storage;

import java.io.Serializable;

import v8_bytecode.structs.TupleStruct;

public final class TupleStore implements Serializable {
	private final String name;
	
	private TupleStore(final String name) {
		this.name = name;
	}
	
	public static TupleStore fromStruct(final TupleStruct struct) {
		return new TupleStore(struct.getName());
	}
	
	public String getName() {
		return name;
	}
}
