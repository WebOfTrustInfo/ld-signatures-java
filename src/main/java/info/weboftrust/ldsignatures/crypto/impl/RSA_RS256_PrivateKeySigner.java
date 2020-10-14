package info.weboftrust.ldsignatures.crypto.impl;

import info.weboftrust.ldsignatures.crypto.PrivateKeySigner;

import java.security.GeneralSecurityException;
import java.security.Signature;
import java.security.interfaces.RSAPrivateKey;

public class RSA_RS256_PrivateKeySigner extends PrivateKeySigner<RSAPrivateKey> {

	public RSA_RS256_PrivateKeySigner(RSAPrivateKey privateKey) {

		super(privateKey, "RS256");
	}

	@Override
	public byte[] sign(byte[] content) throws GeneralSecurityException {

		Signature jcaSignature = Signature.getInstance("SHA256withRSA");

		jcaSignature.initSign(this.getPrivateKey());
		jcaSignature.update(content);

		return jcaSignature.sign();
	}
}
