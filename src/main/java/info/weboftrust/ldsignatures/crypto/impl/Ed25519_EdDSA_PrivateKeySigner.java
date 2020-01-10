package info.weboftrust.ldsignatures.crypto.impl;

import java.security.GeneralSecurityException;

import info.weboftrust.ldsignatures.crypto.PrivateKeySigner;
import info.weboftrust.ldsignatures.crypto.provider.EC25519Provider;

public class Ed25519_EdDSA_PrivateKeySigner extends PrivateKeySigner<byte[]> {

	public Ed25519_EdDSA_PrivateKeySigner(byte[] privateKey) {

		super(privateKey, "EdDSA");
	}

	@Override
	public byte[] sign(byte[] content) throws GeneralSecurityException {

		return EC25519Provider.get().sign(content, this.getPrivateKey());
	}
}
