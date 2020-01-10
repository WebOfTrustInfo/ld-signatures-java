package info.weboftrust.ldsignatures.crypto.provider;

import java.security.GeneralSecurityException;
import java.util.Iterator;
import java.util.ServiceLoader;

public abstract class EC25519Provider {

	private static EC25519Provider instance;

	public static EC25519Provider get() {

		EC25519Provider result = instance;

		if (result == null) {

			synchronized(EC25519Provider.class) {

				result = instance;

				if (result == null) {

					ServiceLoader<EC25519Provider> serviceLoader = ServiceLoader.load(EC25519Provider.class, EC25519Provider.class.getClassLoader());
					Iterator<EC25519Provider> iterator = serviceLoader.iterator();
					if (! iterator.hasNext()) throw new RuntimeException("No " + EC25519Provider.class.getName() + " registered");

					instance = result = iterator.next();
				}
			}
		}

		return result;
	}

	public void set(EC25519Provider instance) {

		EC25519Provider.instance = instance;
	}

	public abstract void generateEC25519KeyPair(byte[] publicKey, byte[] privateKey) throws GeneralSecurityException;
	public abstract void generateEC25519KeyPairFromSeed(byte[] publicKey, byte[] privateKey, byte[] seed) throws GeneralSecurityException;
	public abstract byte[] sign(byte[] content, byte[] privateKey) throws GeneralSecurityException;
	public abstract boolean verify(byte[] content, byte[] signature, byte[] publicKey) throws GeneralSecurityException;
}
