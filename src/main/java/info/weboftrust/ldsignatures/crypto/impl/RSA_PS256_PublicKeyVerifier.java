package info.weboftrust.ldsignatures.crypto.impl;

import info.weboftrust.ldsignatures.crypto.PublicKeyVerifier;

import java.security.GeneralSecurityException;
import java.security.Signature;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;

public class RSA_PS256_PublicKeyVerifier extends PublicKeyVerifier<RSAPublicKey> {

	public RSA_PS256_PublicKeyVerifier(RSAPublicKey publicKey) {

		super(publicKey, "RS256");
	}

	@Override
	public boolean verify(byte[] content, byte[] signature) throws GeneralSecurityException {

		PSSParameterSpec pssParameterSpec = new PSSParameterSpec("SHA256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1);

		Signature jcaSignature = Signature.getInstance("SHA256withRSAandMGF1");
		jcaSignature.setParameter(pssParameterSpec);

		jcaSignature.initVerify(this.getPublicKey());
		jcaSignature.update(content);

		return jcaSignature.verify(signature);
	}
}
