package info.weboftrust.ldsignatures.crypto.impl;

import java.security.GeneralSecurityException;
import java.security.Signature;
import java.security.interfaces.RSAPublicKey;

import info.weboftrust.ldsignatures.crypto.PublicKeyVerifier;

public class RSA_RS256_PublicKeyVerifier extends PublicKeyVerifier<RSAPublicKey> {

	public RSA_RS256_PublicKeyVerifier(RSAPublicKey publicKey) {

		super(publicKey, "RS256");
	}

	@Override
	public boolean verify(byte[] content, byte[] signature) throws GeneralSecurityException {

		Signature jcaSignature = Signature.getInstance("SHA256withRSA");

		jcaSignature.initVerify(this.getPublicKey());
		jcaSignature.update(content);

		return jcaSignature.verify(signature);
	}
}
