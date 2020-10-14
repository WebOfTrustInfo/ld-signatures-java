package info.weboftrust.ldsignatures.crypto.provider.impl;

import info.weboftrust.ldsignatures.crypto.provider.RandomProvider;
import org.abstractj.kalium.NaCl;
import org.abstractj.kalium.NaCl.Sodium;

import java.security.GeneralSecurityException;

public class NaClSodiumRandomProvider extends RandomProvider {

	private Sodium sodium;

	public NaClSodiumRandomProvider() {

		NaCl.init();
		this.sodium = NaCl.sodium();
	}

	@Override
	public byte[] randomBytes(int length) throws GeneralSecurityException {

		byte[] randomBytes = new byte[length];
		sodium.randombytes(randomBytes, 256);

		return randomBytes;
	}
}
