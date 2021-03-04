package v8_bytecode;

import v8_bytecode.enums.ScopeInfoFlagsFuncKindEnum;
import v8_bytecode.enums.ScopeInfoFlagsFuncVar;
import v8_bytecode.enums.ScopeInfoFlagsLang;
import v8_bytecode.enums.ScopeInfoFlagsReceiver;
import v8_bytecode.enums.ScopeInfoFlagsScope;

public final class ScopeInfoFlags {
	
	private final ScopeInfoFlagsScope scope;
	private final boolean callsSloppyEval;
	private final ScopeInfoFlagsLang langMode;
	private final boolean declarationScope;
	private final ScopeInfoFlagsReceiver recv;
	private final boolean hasNewTarget;
	private final ScopeInfoFlagsFuncVar funcVar;
	private final boolean asmModule;
	private final boolean hasSimpleParameters;
	private final ScopeInfoFlagsFuncKindEnum.ScopeInfoFlagsFuncKind kind;
	private final boolean hasOuterScopeInfo;
	private final boolean isDebugEvaluateScope;
	
	public ScopeInfoFlags(int flags) {
		scope = ScopeInfoFlagsScope.fromInt(flags & 0xF);
		callsSloppyEval = ((flags & 0x10) >> 0x04) != 0;
		langMode = ScopeInfoFlagsLang.fromInt((flags & 0x20) >> 0x05);
		declarationScope = ((flags & 0x40) >> 0x06) != 0;
		recv = ScopeInfoFlagsReceiver.fromInt((flags & 0x180) >> 0x07);
		hasNewTarget = ((flags & 0x200) >> 0x09) != 0;
		funcVar = ScopeInfoFlagsFuncVar.fromInt((flags & 0xC00) >> 0x0A);
		asmModule = ((flags & 0x1000) >> 0x0C) != 0;
		hasSimpleParameters = ((flags & 0x2000) >> 0x0D) != 0;
		kind = ScopeInfoFlagsFuncKindEnum.ScopeInfoFlagsFuncKind.fromInt((flags & 0x00FFC000) >> 0x0E);
		hasOuterScopeInfo = ((flags & 0x01000000) >> 0x18) != 0;
		isDebugEvaluateScope = ((flags & 0x02000000) >> 0x19) != 0;
	}
	
	public ScopeInfoFlagsScope getScope() {
		return scope;
	}

	public boolean isCallsSloppyEval() {
		return callsSloppyEval;
	}

	public ScopeInfoFlagsLang getLangMode() {
		return langMode;
	}

	public boolean isDeclarationScope() {
		return declarationScope;
	}

	public ScopeInfoFlagsReceiver getRecv() {
		return recv;
	}

	public boolean hasNewTarget() {
		return hasNewTarget;
	}

	public ScopeInfoFlagsFuncVar getFuncVar() {
		return funcVar;
	}

	public boolean isAsmModule() {
		return asmModule;
	}

	public boolean hasSimpleParameters() {
		return hasSimpleParameters;
	}

	public ScopeInfoFlagsFuncKindEnum.ScopeInfoFlagsFuncKind getKind() {
		return kind;
	}

	public boolean hasOuterScopeInfo() {
		return hasOuterScopeInfo;
	}

	public boolean isDebugEvaluateScope() {
		return isDebugEvaluateScope;
	}
	
	public boolean hasReceiver() {
		return !recv.equals(ScopeInfoFlagsReceiver.UNUSED) && !recv.equals(ScopeInfoFlagsReceiver.NONE);
	}
	
	public boolean hasFunctionVar() {
		return !funcVar.equals(ScopeInfoFlagsFuncVar.NONE);
	}
}
