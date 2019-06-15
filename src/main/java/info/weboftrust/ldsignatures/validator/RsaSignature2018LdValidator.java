package info.weboftrust.ldsignatures.validator;

import java.security.GeneralSecurityException;
import java.security.interfaces.RSAPublicKey;

import org.jose4j.jwa.AlgorithmConstraints;
import org.jose4j.jws.AlgorithmIdentifiers;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.lang.JoseException;

import info.weboftrust.ldsignatures.LdSignature;
import info.weboftrust.ldsignatures.suites.RsaSignature2018SignatureSuite;
import info.weboftrust.ldsignatures.suites.SignatureSuites;

public class RsaSignature2018LdValidator extends LdValidator<RsaSignature2018SignatureSuite> {

	private RSAPublicKey publicKey;

	public RsaSignature2018LdValidator() {

		super(SignatureSuites.SIGNATURE_SUITE_RSASIGNATURE2018);
	}

	public RsaSignature2018LdValidator(RSAPublicKey publicKey) {

		super(SignatureSuites.SIGNATURE_SUITE_RSASIGNATURE2018);

		this.publicKey = publicKey;
	}

	public static boolean validate(String canonicalizedDocument, LdSignature ldSignature, RSAPublicKey publicKey) throws GeneralSecurityException {

		// build the payload

		String unencodedPayload = canonicalizedDocument;

		// build the JWS and validate

		boolean validate;

		try {

			JsonWebSignature jws = new JsonWebSignature();
			jws.setAlgorithmConstraints(new AlgorithmConstraints(AlgorithmConstraints.ConstraintType.WHITELIST, AlgorithmIdentifiers.RSA_USING_SHA256));
			jws.setCompactSerialization(ldSignature.getSignatureValue());
			jws.setPayload(unencodedPayload);

			jws.setKey(publicKey);
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
