package info.weboftrust.ldsignatures.crypto.impl;

import info.weboftrust.ldsignatures.crypto.PrivateKeySigner;
import info.weboftrust.ldsignatures.crypto.provider.Ed25519Provider;

import java.security.GeneralSecurityException;

public class Ed25519_EdDSA_PrivateKeySigner extends PrivateKeySigner<byte[]> {

	public Ed25519_EdDSA_PrivateKeySigner(byte[] privateKey) {

		super(privateKey, "EdDSA");
	}

	@Override
	public byte[] sign(byte[] content) throws GeneralSecurityException {

		return Ed25519Provider.get().sign(content, this.getPrivateKey());
	}
}
