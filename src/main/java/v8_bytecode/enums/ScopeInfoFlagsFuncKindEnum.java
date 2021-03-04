package v8_bytecode.enums;

import ghidra.program.model.data.EnumDataType;

public final class ScopeInfoFlagsFuncKindEnum  extends EnumDataType {

	public enum ScopeInfoFlagsFuncKind {
		NormalFunction(0),
	    ArrowFunction(1 << 0),
	    GeneratorFunction(1 << 1),
	    ConciseMethod(1 << 2),
	    ConciseGeneratorMethod((1 << 1) | (1 << 2)),
	    DefaultConstructor(1 << 3),
	    DerivedConstructor(1 << 4),
	    BaseConstructor(1 << 5),
	    GetterFunction(1 << 6),
	    SetterFunction(1 << 7),
	    AsyncFunction(1 << 8),
	    Module(1 << 9),
	    AccessorFunction((1 << 6) | (1 << 7)),
	    DefaultBaseConstructor((1 << 3) | (1 << 5)),
	    DefaultDerivedConstructor((1 << 3) | (1 << 4)),
	    ClassConstructor((1 << 5) | (1 << 4) | (1 << 3)),
	    AsyncArrowFunction((1 << 0) | (1 << 8)),
	    AsyncConciseMethod((1 << 8) | (1 << 2)),
	    AsyncConciseGeneratorMethod((1 << 8) | ((1 << 1) | (1 << 2))),
	    AsyncGeneratorFunction((1 << 8) | (1 << 1));
		
		private final int value;
		
		ScopeInfoFlagsFuncKind(int value) {
			this.value = value;
		}
		
		public static ScopeInfoFlagsFuncKind fromInt(int value) {
			for (ScopeInfoFlagsFuncKind kind : values()) {
				if (kind.value == value) {
					return kind;
				}
			}
			
			return null;
		}
	}
	
	public ScopeInfoFlagsFuncKindEnum() {
		super("SIF_KIND", 4);
		
		for (ScopeInfoFlagsFuncKind type : ScopeInfoFlagsFuncKind.values()) {
			add(type.name(), type.value);
		}
	}
	
}
