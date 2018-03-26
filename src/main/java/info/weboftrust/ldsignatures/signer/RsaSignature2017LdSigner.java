package info.weboftrust.ldsignatures.signer;

import java.net.URI;
import java.security.GeneralSecurityException;
import java.security.interfaces.RSAPrivateKey;

import org.jose4j.jws.AlgorithmIdentifiers;
import org.jose4j.lang.JoseException;

import info.weboftrust.ldsignatures.jws.RFC7797JsonWebSignature;
import info.weboftrust.ldsignatures.suites.RsaSignature2017SignatureSuite;
import info.weboftrust.ldsignatures.suites.SignatureSuites;

public class RsaSignature2017LdSigner extends LdSigner<RsaSignature2017SignatureSuite> {

	private static String JWS_HEADER_STRING = "{\"alg\":\"RS256\",\"b64\":false,\"crit\":[\"b64\"]}";
	private static String[] KNOWN_CRITICAL_HEADERS = new String[] { "b64" };

	private RSAPrivateKey privateKey;

	public RsaSignature2017LdSigner() {

		super(SignatureSuites.SIGNATURE_SUITE_RSASIGNATURE2017);
	}

	public RsaSignature2017LdSigner(URI creator, String created, String domain, String nonce, RSAPrivateKey privateKey) {

		super(SignatureSuites.SIGNATURE_SUITE_RSASIGNATURE2017, creator, created, domain, nonce);

		this.privateKey = privateKey;
	}

	public static String sign(String canonicalizedDocument, RSAPrivateKey privateKey) throws GeneralSecurityException {

		// build the payload

		String unencodedPayload = canonicalizedDocument;

		// build the JWS header and payload

		RFC7797JsonWebSignature jws = new RFC7797JsonWebSignature(JWS_HEADER_STRING, unencodedPayload);
		jws.setAlgorithmHeaderValue(AlgorithmIdentifiers.RSA_USING_SHA256);
		jws.setKnownCriticalHeaders(KNOWN_CRITICAL_HEADERS);

		// sign the payload and build the JWS

		jws.setKey(privateKey);

		String signatureValue;

		try {

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
