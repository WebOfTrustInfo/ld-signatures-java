package info.weboftrust.ldsignatures.crypto.provider.impl;

import info.weboftrust.ldsignatures.crypto.provider.SHA256Provider;
import org.abstractj.kalium.NaCl;
import org.abstractj.kalium.NaCl.Sodium;

import java.security.GeneralSecurityException;

public class NaClSodiumSHA256Provider extends SHA256Provider {

	private Sodium sodium;

	public NaClSodiumSHA256Provider() {

		NaCl.init();
		this.sodium = NaCl.sodium();
	}

	@Override
	public byte[] sha256(byte[] bytes) throws GeneralSecurityException {

		byte[] buffer = new byte[32];
		sodium.crypto_hash_sha256(buffer, bytes, bytes.length);

		return buffer;
	}
}
