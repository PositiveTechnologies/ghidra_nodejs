package v8_bytecode;

import java.io.File;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

import com.google.gson.JsonArray;

import ghidra.framework.Application;
import v8_bytecode.allocator.JscParser;

public final class V8_VersionDetector {
	private final Map<Long, String> verHashes32;
	private final Map<Long, String> verHashes64;
	
	public V8_VersionDetector() throws IOException {
		verHashes32 = new HashMap<>();
		verHashes64 = new HashMap<>();
		
		File file = Application.getModuleDataFile("v8_versions.json").getFile(false);
		final JsonArray versions = JscParser.jsonArrayFromFile(file.getAbsolutePath());
		
		for (final var version : versions) {
			final String ver = version.getAsString();
			final String[] mmbp = ver.split("\\.");
			
			if (mmbp.length != 4) {
				continue;
			}

			final var hash32 = versionHash(
					Integer.parseInt(mmbp[0]),
					Integer.parseInt(mmbp[1]),
					Integer.parseInt(mmbp[2]),
					Integer.parseInt(mmbp[3])
					);
			
			final var hash64 = versionHash64(
					Integer.parseInt(mmbp[0]),
					Integer.parseInt(mmbp[1]),
					Integer.parseInt(mmbp[2]),
					Integer.parseInt(mmbp[3])
					);
			
			verHashes32.put(hash32, ver);
			verHashes64.put(hash64, ver);
		}
	}
	
	private static long hashValueUnsigned(long v) {
		v = ((v << 15L) - v - 1L) & 0xFFFFFFFFL;
	    v = (v ^ (v >>> 12L)) & 0xFFFFFFFFL;
	    v = (v + (v << 2L)) & 0xFFFFFFFFL;
	    v = (v ^ (v >>> 4L)) & 0xFFFFFFFFL;
	    v = (v * 2057L) & 0xFFFFFFFFL;
	    v = (v ^ (v >>> 16L)) & 0xFFFFFFFFL;
	    return v;
	}
	
	private static long hashCombine(long seed, long value) {
		value = (value * 0xCC9E2D51L) & 0xFFFFFFFFL;
		value = ((value >>> 15L) | (value << (32L-15L))) & 0xFFFFFFFFL;
		value = (value * 0x1b873593L) & 0xFFFFFFFFL;
		seed ^= value;
		seed = ((seed >>> 13L) | (seed << (32L-13L))) & 0xFFFFFFFFL;
		seed = (seed * 5L + 0xE6546B64L) & 0xFFFFFFFFL;
		return seed;
	}
	
	private static long hashCombine64(long seed, long value) {
		final var m = 0xC6A4A7935BD1E995L;
		value = (value * m) & 0xFFFFFFFFFFFFFFFFL;
		value = (value ^ (value >>> 47L)) & 0xFFFFFFFFFFFFFFFFL;
		value = (value * m) & 0xFFFFFFFFFFFFFFFFL;
		seed = (seed ^ value) & 0xFFFFFFFFFFFFFFFFL;
		seed = (seed * m) & 0xFFFFFFFFFFFFFFFFL;
		return seed;
	}
	
	private static long versionHash(int major, int minor, int build, int patch) {
		var seed = 0L;
		var v = hashValueUnsigned(patch);
	    seed = hashCombine(seed, v);
	    v = hashValueUnsigned(build);
	    seed = hashCombine(seed, v);
	    v = hashValueUnsigned(minor);
	    seed = hashCombine(seed, v);
	    v = hashValueUnsigned(major);
	    seed = hashCombine(seed, v);
	    return seed;
	}
	
	private static long versionHash64(int major, int minor, int build, int patch) {
		var seed = 0L;
		var v = hashValueUnsigned(patch);
	    seed = hashCombine64(seed, v);
	    v = hashValueUnsigned(build);
	    seed = hashCombine64(seed, v);
	    v = hashValueUnsigned(minor);
	    seed = hashCombine64(seed, v);
	    v = hashValueUnsigned(major);
	    seed = hashCombine64(seed, v);
	    return seed & 0xFFFFFFFFL;
	}
	
	public String detectVersion(long hash) {
		final var ver32 = verHashes32.getOrDefault(hash, null);
		
		if (ver32 != null) {
			return ver32;
		}
		
		final var ver64 = verHashes64.getOrDefault(hash, null);
		
		if (ver64 != null) {
			return ver64;
		}
		
		return "Unknown";
	}
	
	public boolean detectBitness(long hash) throws IOException {
		final var is32bit = verHashes32.containsKey(hash);
		
		if (is32bit) {
			return is32bit;
		}
		
		final var is64bit = verHashes64.containsKey(hash);
		
		if (is64bit) {
			return false;
		}
		
		throw new IOException("Unknown bitness!");
	}
}
