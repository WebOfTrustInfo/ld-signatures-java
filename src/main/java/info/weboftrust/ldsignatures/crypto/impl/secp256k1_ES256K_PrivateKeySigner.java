package info.weboftrust.ldsignatures.crypto.impl;

import com.nimbusds.jose.JWSAlgorithm;
import info.weboftrust.ldsignatures.crypto.PrivateKeySigner;
import org.bitcoinj.core.ECKey;
import org.bitcoinj.core.Sha256Hash;

import java.security.GeneralSecurityException;

public class secp256k1_ES256K_PrivateKeySigner extends PrivateKeySigner<ECKey> {

	public secp256k1_ES256K_PrivateKeySigner(ECKey privateKey) {

		super(privateKey, JWSAlgorithm.ES256K.getName());
	}

	@Override
	public byte[] sign(byte[] content) throws GeneralSecurityException {

		return this.getPrivateKey().sign(Sha256Hash.of(content)).encodeToDER();
	}
}
