package info.weboftrust.ldsignatures.signer;

import java.security.GeneralSecurityException;
import java.security.interfaces.RSAPrivateKey;
import java.util.Collections;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.Payload;

import info.weboftrust.ldsignatures.crypto.ByteSigner;
import info.weboftrust.ldsignatures.crypto.adapter.JWSSignerAdapter;
import info.weboftrust.ldsignatures.crypto.impl.RSA_RS256_PrivateKeySigner;
import info.weboftrust.ldsignatures.suites.RsaSignature2018SignatureSuite;
import info.weboftrust.ldsignatures.suites.SignatureSuites;

public class RsaSignature2018LdSigner extends LdSigner<RsaSignature2018SignatureSuite> {

	private ByteSigner signer;

	public RsaSignature2018LdSigner(ByteSigner signer) {

		super(SignatureSuites.SIGNATURE_SUITE_RSASIGNATURE2018);

		this.signer = signer;
	}

	public RsaSignature2018LdSigner(RSAPrivateKey privateKey) {

		this(new RSA_RS256_PrivateKeySigner(privateKey));
	}

	public RsaSignature2018LdSigner() {

		this((ByteSigner) null);
	}

	public static String sign(String canonicalizedDocument, ByteSigner signer) throws GeneralSecurityException {

		// build the payload

		String unencodedPayload = canonicalizedDocument;

		// build the JWS and sign

		String signatureValue;

		try {

			JWSHeader jwsHeader = new JWSHeader.Builder(JWSAlgorithm.RS256)
					.customParam("b64", Boolean.FALSE)
					.criticalParams(Collections.singleton("b64"))
					.build();

			Payload payload = new Payload(unencodedPayload);

			JWSObject jwsObject = new JWSObject(jwsHeader, payload);

			JWSSigner jwsSigner = new JWSSignerAdapter(signer, JWSAlgorithm.RS256);
			jwsObject.sign(jwsSigner);
			signatureValue = jwsObject.serialize(true);

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

		return signatureValue;
	}

	@Override
	public String sign(String canonicalizedDocument) throws GeneralSecurityException {

		return sign(canonicalizedDocument, this.getSigner());
	}

	/*
	 * Getters and setters
	 */

	public ByteSigner getSigner() {

		return this.signer;
	}

	public void setSigner(ByteSigner signer) {

		this.signer = signer;
	}
}
