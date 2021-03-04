package v8_bytecode.storage;

import static java.util.Map.entry;

import java.io.Serializable;
import java.util.List;
import java.util.Map;

import v8_bytecode.RuntimeFuncArg;

public final class RuntimesIntrinsicsStore implements Serializable {
	private final List<List<RuntimeFuncArg>> allArgs;
	private final List<String> names;
	
	private static final Map<Integer, Integer> intrinsicsToRuntimes = Map.ofEntries(
	        entry(0, 741),
	        entry(1, 740),
	        entry(2, 742),
	        entry(3, 734),
	        entry(4, 738),
	        entry(5, 745),
	        entry(6, 739),
	        entry(7, 735),
	        entry(8, 730),
	        entry(9, 887),
	        entry(10, 905),
	        entry(11, 778),
	        entry(12, 869),
	        entry(13, 582),
	        entry(14, 631),
	        entry(15, 941),
	        entry(16, 886),
	        entry(17, 632),
	        entry(18, 633),
	        entry(19, 634),
	        entry(20, 851),
	        entry(21, 1094),
	        entry(22, 990),
	        entry(23, 899),
	        entry(24, 898),
	        entry(25, 897),
	        entry(26, 896),
	        entry(27, 893)
			);
	
	public RuntimesIntrinsicsStore(final List<String> names, final List<List<RuntimeFuncArg>> allArgs) {
		this.allArgs = allArgs;
		this.names = names;
	}
	
	public List<RuntimeFuncArg> getArgs(int index) {
		return allArgs.get(index);
	}
	
	public List<String> getNames() {
		return names;
	}
	
	public int getNamesCount() {
		return names.size();
	}
	
	public String getRuntimeName(int index) {
		return names.get(index);
	}
	
	public int getIntrinsicsCount() {
		return intrinsicsToRuntimes.size();
	}
	
	public String getIntrinsicName(int index) {
		return String.format("_%s", names.get(intrinsicsToRuntimes.get(index) - names.size()));
	}
}
