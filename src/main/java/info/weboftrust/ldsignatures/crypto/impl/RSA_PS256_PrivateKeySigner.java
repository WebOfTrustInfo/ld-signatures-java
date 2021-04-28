package info.weboftrust.ldsignatures.crypto.impl;

import com.nimbusds.jose.JWSAlgorithm;
import info.weboftrust.ldsignatures.crypto.PrivateKeySigner;

import java.security.GeneralSecurityException;
import java.security.Signature;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;

public class RSA_PS256_PrivateKeySigner extends PrivateKeySigner<RSAPrivateKey> {

	public RSA_PS256_PrivateKeySigner(RSAPrivateKey privateKey) {

		super(privateKey, JWSAlgorithm.PS256.getName());
	}

	@Override
	public byte[] sign(byte[] content) throws GeneralSecurityException {

		PSSParameterSpec pssParameterSpec = new PSSParameterSpec("SHA256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1);

		Signature jcaSignature = Signature.getInstance("SHA256withRSAandMGF1");
		jcaSignature.setParameter(pssParameterSpec);

		jcaSignature.initSign(this.getPrivateKey());
		jcaSignature.update(content);

		return jcaSignature.sign();
	}
}
