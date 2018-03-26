package info.weboftrust.ldsignatures.validator;

import java.security.GeneralSecurityException;
import java.security.interfaces.RSAPublicKey;

import org.jose4j.jws.AlgorithmIdentifiers;
import org.jose4j.lang.JoseException;

import info.weboftrust.ldsignatures.LdSignature;
import info.weboftrust.ldsignatures.jws.RFC7797JsonWebSignature;
import info.weboftrust.ldsignatures.suites.RsaSignature2017SignatureSuite;
import info.weboftrust.ldsignatures.suites.SignatureSuites;

public class RsaSignature2017LdValidator extends LdValidator<RsaSignature2017SignatureSuite> {

	private static String JWS_HEADER_STRING = "{\"alg\":\"RS256\",\"b64\":false,\"crit\":[\"b64\"]}";
	private static String[] KNOWN_CRITICAL_HEADERS = new String[] { "b64" };

	private RSAPublicKey publicKey;

	public RsaSignature2017LdValidator() {

		super(SignatureSuites.SIGNATURE_SUITE_RSASIGNATURE2017);
	}

	public RsaSignature2017LdValidator(RSAPublicKey publicKey) {

		super(SignatureSuites.SIGNATURE_SUITE_RSASIGNATURE2017);

		this.publicKey = publicKey;
	}

	public static boolean validate(String canonicalizedDocument, LdSignature ldSignature, RSAPublicKey publicKey) throws GeneralSecurityException {

		// build the payload

		String unencodedPayload = canonicalizedDocument;

		// build the JWS header and payload

		RFC7797JsonWebSignature jws = new RFC7797JsonWebSignature(JWS_HEADER_STRING, unencodedPayload);
		jws.setAlgorithmHeaderValue(AlgorithmIdentifiers.RSA_USING_SHA256);
		jws.setKnownCriticalHeaders(KNOWN_CRITICAL_HEADERS);

		// validate the signature on the payload

		jws.setKey(publicKey);

		boolean validate;

		try {

			jws.setCompactSerialization(ldSignature.getSignatureValue());

			validate = jws.verifySignature();
		} catch (JoseException ex) {

			throw new GeneralSecurityException("JOSE validation problem: " + ex.getMessage(), ex);
		}

		// done

		return validate;
	}

	@Override
	public boolean validate(String canonicalizedDocument, LdSignature ldSignature) throws GeneralSecurityException {

		return validate(canonicalizedDocument, ldSignature, this.publicKey);
	}

	/*
	 * Getters and setters
	 */

	public RSAPublicKey getPublicKey() {

		return this.publicKey;
	}

	public void setPublicKey(RSAPublicKey publicKey) {

		this.publicKey = publicKey;
	}
}
