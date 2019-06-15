package info.weboftrust.ldsignatures.signer;

import java.net.URI;
import java.security.GeneralSecurityException;
import java.security.interfaces.RSAPrivateKey;

import org.jose4j.jws.AlgorithmIdentifiers;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwx.HeaderParameterNames;
import org.jose4j.lang.JoseException;

import info.weboftrust.ldsignatures.suites.RsaSignature2018SignatureSuite;
import info.weboftrust.ldsignatures.suites.SignatureSuites;

public class RsaSignature2018LdSigner extends LdSigner<RsaSignature2018SignatureSuite> {

	private RSAPrivateKey privateKey;

	public RsaSignature2018LdSigner() {

		super(SignatureSuites.SIGNATURE_SUITE_RSASIGNATURE2018);
	}

	public RsaSignature2018LdSigner(URI creator, String created, String domain, String nonce, RSAPrivateKey privateKey) {

		super(SignatureSuites.SIGNATURE_SUITE_RSASIGNATURE2018, creator, created, domain, nonce);

		this.privateKey = privateKey;
	}

	public static String sign(String canonicalizedDocument, RSAPrivateKey privateKey) throws GeneralSecurityException {

		// build the payload

		String unencodedPayload = canonicalizedDocument;

		// build the JWS and sign

		String signatureValue;

		try {

			JsonWebSignature jws = new JsonWebSignature();
			jws.setAlgorithmHeaderValue(AlgorithmIdentifiers.RSA_USING_SHA256);
			jws.getHeaders().setObjectHeaderValue(HeaderParameterNames.BASE64URL_ENCODE_PAYLOAD, false);
			jws.setCriticalHeaderNames(HeaderParameterNames.BASE64URL_ENCODE_PAYLOAD);
			jws.setPayload(unencodedPayload);

			jws.setKey(privateKey);
			signatureValue = jws.getDetachedContentCompactSerialization();
		} catch (JoseException ex) {

			throw new GeneralSecurityException("JOSE signing problem: " + ex.getMessage(), ex);
		}

		// done

		return signatureValue;
	}

	@Override
	public String sign(String canonicalizedDocument) throws GeneralSecurityException {

		return sign(canonicalizedDocument, this.privateKey);
	}

	/*
	 * Getters and setters
	 */

	public RSAPrivateKey getPrivateKey() {

		return this.privateKey;
	}

	public void setPrivateKey(RSAPrivateKey privateKey) {

		this.privateKey = privateKey;
	}
}
