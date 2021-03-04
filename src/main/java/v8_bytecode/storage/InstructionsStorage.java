package v8_bytecode.storage;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;

import ghidra.program.model.listing.Program;
import ghidra.program.model.util.ObjectPropertyMap;
import ghidra.program.model.util.PropertyMapManager;
import ghidra.util.ObjectStorage;
import ghidra.util.PrivateSaveable;
import ghidra.util.exception.DuplicateNameException;

public final class InstructionsStorage extends PrivateSaveable {
	private long addr;
	private ScopeInfoStore store;
	
	public InstructionsStorage() {
		
	}
	
	private InstructionsStorage(long addr, ScopeInfoStore store) {
		this.addr = addr;
		this.store = store;
	}
	
	public ScopeInfoStore getScopeInfo() {
		return store;
	}
	
	public static void create(Program program, long address, ScopeInfoStore store) {
		PropertyMapManager mgr = program.getUsrPropertyManager();

		InstructionsStorage result = new InstructionsStorage(address, store);
		
		try {
			ObjectPropertyMap map = mgr.createObjectPropertyMap(String.format("IS_%d", address), InstructionsStorage.class);
			map.add(program.getAddressFactory().getDefaultAddressSpace().getAddress(address), result);
		} catch (DuplicateNameException e) {
		}
	}
	
	public static InstructionsStorage load(Program program, long address) {
		PropertyMapManager mgr = program.getUsrPropertyManager();
		ObjectPropertyMap map = mgr.getObjectPropertyMap(String.format("IS_%d", address));
		
		if (map == null) {
			return null;
		}

		return (InstructionsStorage) map.getObject(program.getAddressFactory().getDefaultAddressSpace().getAddress(address));
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
			objStream.writeLong(addr);
			objStream.writeObject(store);
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

	@Override
	public void restore(ObjectStorage objStorage) {
		ByteArrayInputStream stream = new ByteArrayInputStream(objStorage.getBytes());
		
		try {
			ObjectInputStream objStream = new ObjectInputStream(stream);
			addr = objStream.readLong();
			store = (ScopeInfoStore) objStream.readObject();
			objStream.close();
		} catch (IOException | ClassNotFoundException unused) {
		} finally {
			try {
				stream.close();
			} catch (IOException unused) {
			}
		}
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
