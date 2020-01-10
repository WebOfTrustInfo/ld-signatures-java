package info.weboftrust.ldsignatures.crypto.impl;

import java.security.GeneralSecurityException;

import info.weboftrust.ldsignatures.crypto.PublicKeyVerifier;
import info.weboftrust.ldsignatures.crypto.provider.EC25519Provider;

public class Ed25519_EdDSA_PublicKeyVerifier extends PublicKeyVerifier<byte[]> {

	public Ed25519_EdDSA_PublicKeyVerifier(byte[] publicKey) {

		super(publicKey, "EdDSA");
	}

	@Override
	public boolean verify(byte[] content, byte[] signature) throws GeneralSecurityException {

		return EC25519Provider.get().verify(content, signature, this.getPublicKey());
	}
}
