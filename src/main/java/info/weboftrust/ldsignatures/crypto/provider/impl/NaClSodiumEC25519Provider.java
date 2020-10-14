package info.weboftrust.ldsignatures.crypto.provider.impl;

import info.weboftrust.ldsignatures.crypto.provider.EC25519Provider;
import info.weboftrust.ldsignatures.crypto.provider.RandomProvider;
import info.weboftrust.ldsignatures.crypto.provider.SHA256Provider;
import jnr.ffi.byref.LongLongByReference;
import org.abstractj.kalium.NaCl;
import org.abstractj.kalium.NaCl.Sodium;

import java.security.GeneralSecurityException;
import java.util.Arrays;

public class NaClSodiumEC25519Provider extends EC25519Provider {

	private Sodium sodium;

	public NaClSodiumEC25519Provider() {

		NaCl.init();
		this.sodium = NaCl.sodium();
	}

	@Override
	public void generateEC25519KeyPair(byte[] publicKey, byte[] privateKey) throws GeneralSecurityException {

		if (privateKey.length != Sodium.CRYPTO_SIGN_ED25519_SECRETKEYBYTES) throw new GeneralSecurityException("Invalid private key length: " + privateKey.length);
		if (publicKey.length != Sodium.CRYPTO_SIGN_ED25519_PUBLICKEYBYTES) throw new GeneralSecurityException("Invalid public key length: "+ publicKey.length);

		// create seed

		byte[] seed = RandomProvider.get().randomBytes(256);
		seed = SHA256Provider.get().sha256(seed);

		// create key pair

		sodium.crypto_sign_ed25519_seed_keypair(publicKey, privateKey, seed);
		System.arraycopy(publicKey, 0, privateKey, Sodium.CRYPTO_SIGN_ED25519_PUBLICKEYBYTES, Sodium.CRYPTO_SIGN_ED25519_PUBLICKEYBYTES);
	}

	@Override
	public void generateEC25519KeyPairFromSeed(byte[] publicKey, byte[] privateKey, byte[] seed) throws GeneralSecurityException {

		if (privateKey.length != Sodium.CRYPTO_SIGN_ED25519_SECRETKEYBYTES) throw new GeneralSecurityException("Invalid private key length: " + privateKey.length);
		if (publicKey.length != Sodium.CRYPTO_SIGN_ED25519_PUBLICKEYBYTES) throw new GeneralSecurityException("Invalid public key length: " + publicKey.length);

		// create key pair

		sodium.crypto_sign_ed25519_seed_keypair(publicKey, privateKey, seed);
		System.arraycopy(publicKey, 0, privateKey, Sodium.CRYPTO_SIGN_ED25519_PUBLICKEYBYTES, Sodium.CRYPTO_SIGN_ED25519_PUBLICKEYBYTES);
	}

	@Override
	public byte[] sign(byte[] content, byte[] privateKey) throws GeneralSecurityException {

		if (privateKey.length != Sodium.CRYPTO_SIGN_ED25519_SECRETKEYBYTES) throw new GeneralSecurityException("Invalid private key length: " + privateKey.length);

		byte[] signatureValue = new byte[Sodium.CRYPTO_SIGN_ED25519_BYTES + content.length];
		Arrays.fill(signatureValue, 0, Sodium.CRYPTO_SIGN_ED25519_BYTES, (byte) 0);
		System.arraycopy(content, 0, signatureValue, Sodium.CRYPTO_SIGN_ED25519_BYTES, content.length);

		LongLongByReference bufferLen = new LongLongByReference();

		int ret = sodium.crypto_sign_ed25519(signatureValue, bufferLen, content, content.length, privateKey);
		if (ret != 0) throw new GeneralSecurityException("Signing error: " + ret);

		signatureValue = Arrays.copyOfRange(signatureValue, 0, Sodium.CRYPTO_SIGN_ED25519_BYTES);

		return signatureValue;
	}

	@Override
	public boolean verify(byte[] content, byte[] signature, byte[] publicKey) throws GeneralSecurityException {

		if (signature.length != Sodium.CRYPTO_SIGN_ED25519_BYTES) throw new GeneralSecurityException("Invalid signature length: " + signature.length);
		if (publicKey.length != Sodium.CRYPTO_SIGN_ED25519_PUBLICKEYBYTES) throw new GeneralSecurityException("Invalid public key length: " + publicKey.length);

		byte[] sigAndMsg = new byte[signature.length + content.length];
		System.arraycopy(signature, 0, sigAndMsg, 0, signature.length);
		System.arraycopy(content, 0, sigAndMsg, signature.length, content.length);

		byte[] buffer = new byte[sigAndMsg.length];
		LongLongByReference bufferLen = new LongLongByReference();

		int ret = NaCl.sodium().crypto_sign_ed25519_open(buffer, bufferLen, sigAndMsg, sigAndMsg.length, publicKey);
		if (ret != 0) return false;

		buffer = Arrays.copyOf(buffer, buffer.length - Sodium.CRYPTO_SIGN_ED25519_BYTES);

		return Arrays.equals(content, buffer);
	}
}
