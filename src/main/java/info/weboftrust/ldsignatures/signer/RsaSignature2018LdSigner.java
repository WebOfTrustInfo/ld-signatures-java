package info.weboftrust.ldsignatures.signer;

import java.security.GeneralSecurityException;
import java.security.interfaces.RSAPrivateKey;
import java.util.Collections;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.util.Base64URL;

import info.weboftrust.ldsignatures.crypto.ByteSigner;
import info.weboftrust.ldsignatures.crypto.adapter.JWSSignerAdapter;
import info.weboftrust.ldsignatures.crypto.impl.RSA_RS256_PrivateKeySigner;
import info.weboftrust.ldsignatures.suites.RsaSignature2018SignatureSuite;
import info.weboftrust.ldsignatures.suites.SignatureSuites;
import info.weboftrust.ldsignatures.util.JWSUtil;

public class RsaSignature2018LdSigner extends LdSigner<RsaSignature2018SignatureSuite> {

	public RsaSignature2018LdSigner(ByteSigner signer) {

		super(SignatureSuites.SIGNATURE_SUITE_RSASIGNATURE2018, signer);
	}

	public RsaSignature2018LdSigner(RSAPrivateKey privateKey) {

		this(new RSA_RS256_PrivateKeySigner(privateKey));
	}

	public RsaSignature2018LdSigner() {

		this((ByteSigner) null);
	}

	public static String sign(byte[] signingInput, ByteSigner signer) throws GeneralSecurityException {

		// build the JWS and sign

		String jws;

		try {

			JWSHeader jwsHeader = new JWSHeader.Builder(JWSAlgorithm.RS256).customParam("b64", Boolean.FALSE).criticalParams(Collections.singleton("b64")).build();
			byte[] jwsSigningInput = JWSUtil.getJwsSigningInput(jwsHeader, signingInput);

			JWSSigner jwsSigner = new JWSSignerAdapter(signer, JWSAlgorithm.RS256);
			Base64URL signature = jwsSigner.sign(jwsHeader, jwsSigningInput);
			jws = JWSUtil.serializeDetachedJws(jwsHeader, signature);

			/*			JsonWebSignature jws = new JsonWebSignature();
			jws.setAlgorithmHeaderValue(AlgorithmIdentifiers.RSA_USING_SHA256);
			jws.getHeaders().setObjectHeaderValue(HeaderParameterNames.BASE64URL_ENCODE_PAYLOAD, false);
			jws.setCriticalHeaderNames(HeaderParameterNames.BASE64URL_ENCODE_PAYLOAD);
			jws.setPayload(unencodedPayload);

			jws.setKey(privateKey);
			signatureValue = jws.getDetachedContentCompactSerialization();*/
		} catch (JOSEException ex) {

			throw new GeneralSecurityException("JOSE signing problem: " + ex.getMessage(), ex);
		}

		// done

		return jws;
	}

	@Override
	public String sign(byte[] signingInput) throws GeneralSecurityException {

		return sign(signingInput, this.getSigner());
	}
}
