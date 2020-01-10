package info.weboftrust.ldsignatures.crypto.impl;

import java.security.GeneralSecurityException;

import org.bitcoinj.core.ECKey;
import org.bitcoinj.core.Sha256Hash;

import info.weboftrust.ldsignatures.crypto.PrivateKeySigner;

public class P256K_ES256K_PrivateKeySigner extends PrivateKeySigner<ECKey> {

	public P256K_ES256K_PrivateKeySigner(ECKey privateKey) {

		super(privateKey, "ES256K");
	}

	@Override
	public byte[] sign(byte[] content) throws GeneralSecurityException {

		return this.getPrivateKey().sign(Sha256Hash.of(content)).encodeToDER();
	}
}
