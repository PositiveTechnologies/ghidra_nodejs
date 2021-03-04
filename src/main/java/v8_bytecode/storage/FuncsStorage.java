package v8_bytecode.storage;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.util.HashSet;
import java.util.Set;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.util.ObjectPropertyMap;
import ghidra.program.model.util.PropertyMapManager;
import ghidra.util.ObjectStorage;
import ghidra.util.PrivateSaveable;
import ghidra.util.exception.DuplicateNameException;
import v8_bytecode.EnumsStorage;

public final class FuncsStorage extends PrivateSaveable {

	private static final long STOR_ADDR = 0x80000000L;

	private RootsStore rootsEnum = null;
	private RuntimesIntrinsicsStore runsIntrsStore = null;
	private Set<SharedFunctionStore> sharedFuncs = new HashSet<>();
	
	public FuncsStorage() {
		
	}
	
	private FuncsStorage(final EnumsStorage store) {
		this.rootsEnum = store.getRoots();
		this.runsIntrsStore = store.getRuntimesIntrinsicsStore();
	}
	
	public static FuncsStorage create(Program program, final EnumsStorage store) {
		PropertyMapManager mgr = program.getUsrPropertyManager();

		FuncsStorage result = new FuncsStorage(store);
		
		try {
			ObjectPropertyMap map = mgr.createObjectPropertyMap("FS", FuncsStorage.class);
			map.add(program.getAddressFactory().getDefaultAddressSpace().getAddress(STOR_ADDR), result);
		} catch (DuplicateNameException e) {
		}
		
		return result;
	}
	
	public static FuncsStorage load(Program program) {
		PropertyMapManager mgr = program.getUsrPropertyManager();
		ObjectPropertyMap map = mgr.getObjectPropertyMap("FS");

		return (FuncsStorage) map.getObject(program.getAddressFactory().getDefaultAddressSpace().getAddress(STOR_ADDR));
	}
	
	public void store(Program program) {
		int transId = program.startTransaction("Save FuncsStorage");
		
		PropertyMapManager mgr = program.getUsrPropertyManager();
		ObjectPropertyMap map = mgr.getObjectPropertyMap("FS");
		map.remove(program.getAddressFactory().getDefaultAddressSpace().getAddress(STOR_ADDR));
		map.add(program.getAddressFactory().getDefaultAddressSpace().getAddress(STOR_ADDR), this);
		
		program.endTransaction(transId, true);
	}
	
	@Override
	public Class<?>[] getObjectStorageFields() {
		return new Class[] {byte[].class};
	}

	@Override
	public void save(ObjectStorage objStorage) {
		ByteArrayOutputStream stream = new ByteArrayOutputStream();
		
		try {
			ObjectOutputStream objStream = new ObjectOutputStream(stream);
			
			objStream.writeObject(sharedFuncs);
			objStream.writeObject(rootsEnum);
			objStream.writeObject(runsIntrsStore);
			objStream.flush();
			
			byte[] bytes = stream.toByteArray();
			
			objStorage.putBytes(bytes);
		} catch (IOException e) {
			e.printStackTrace();
		} finally {
			try {
				stream.close();
			} catch (IOException e) {
			}
		}
	}

	@SuppressWarnings("unchecked")
	@Override
	public void restore(ObjectStorage objStorage) {
		ByteArrayInputStream stream = new ByteArrayInputStream(objStorage.getBytes());
		
		try {
			ObjectInputStream objStream = new ObjectInputStream(stream);

			sharedFuncs = (Set<SharedFunctionStore>) objStream.readObject();
			rootsEnum = (RootsStore) objStream.readObject();
			runsIntrsStore = (RuntimesIntrinsicsStore) objStream.readObject();

			objStream.close();
		} catch (IOException | ClassNotFoundException unused) {
		} finally {
			try {
				stream.close();
			} catch (IOException unused) {
			}
		}
	}
	
	public RootsStore getRoots() {
		return rootsEnum;
	}
	
	public RuntimesIntrinsicsStore getRuntimesIntrinsicsStore() {
		return runsIntrsStore;
	}
	
	public void addToSharedFunctions(final SharedFunctionStore func) {
		sharedFuncs.add(func);
	}
	
	private SharedFunctionStore getSharedFunction(final Address addrInFunc) {
		for (final SharedFunctionStore func : sharedFuncs) {
			if (func.contains(addrInFunc.getOffset())) {
				return func;
			}
		}
		
		return null;
	}
	
	public ScopeInfoStore getScopeInfo(final Address addr, final String reg) {
		final SharedFunctionStore sharedFunc = getSharedFunction(addr);
		return sharedFunc.getScopeInfo(reg);
	}
	
	public ScopeInfoStore getOuterScopeInfo(final Address addr) {
		final SharedFunctionStore sharedFunc = getSharedFunction(addr);
		return sharedFunc.getOuterScopeInfo();
	}
	
	public void pushScopeInfo(final Address addr, final String reg, final ScopeInfoStore scope) {
		final SharedFunctionStore sharedFunc = getSharedFunction(addr);
		sharedFunc.pushScopeInfo(reg, scope);
	}
	
	public ScopeInfoStore popScopeInfo(final Address addr, final String reg) {
		final SharedFunctionStore sharedFunc = getSharedFunction(addr);
		return sharedFunc.popScopeInfo(reg);
	}
	
	public Object getConstItem(final Address addr, int index) {
		final SharedFunctionStore sharedFunc = getSharedFunction(addr);
		final ConstantPoolStore cp = sharedFunc.getConstantPool();
		return cp.getConstItem(index);
	}
	
	public long getConstItemAddress(final Address addr, int index) {
		final SharedFunctionStore sharedFunc = getSharedFunction(addr);
		final ConstantPoolStore cp = sharedFunc.getConstantPool();
		return cp.getConstItemAddress(index);
	}

	@Override
	public int getSchemaVersion() {
		return 0;
	}

	@Override
	public boolean isUpgradeable(int oldSchemaVersion) {
		return false;
	}

	@Override
	public boolean upgrade(ObjectStorage oldObjStorage, int oldSchemaVersion, ObjectStorage currentObjStorage) {
		return false;
	}
}
