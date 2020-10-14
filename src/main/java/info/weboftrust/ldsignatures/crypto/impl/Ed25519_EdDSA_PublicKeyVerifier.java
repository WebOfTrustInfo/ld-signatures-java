package info.weboftrust.ldsignatures.crypto.impl;

import info.weboftrust.ldsignatures.crypto.PublicKeyVerifier;
import info.weboftrust.ldsignatures.crypto.provider.Ed25519Provider;

import java.security.GeneralSecurityException;

public class Ed25519_EdDSA_PublicKeyVerifier extends PublicKeyVerifier<byte[]> {

	public Ed25519_EdDSA_PublicKeyVerifier(byte[] publicKey) {

		super(publicKey, "EdDSA");
	}

	@Override
	public boolean verify(byte[] content, byte[] signature) throws GeneralSecurityException {

		return Ed25519Provider.get().verify(content, signature, this.getPublicKey());
	}
}
