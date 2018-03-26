package info.weboftrust.ldsignatures.validator;

import java.security.GeneralSecurityException;
import java.util.LinkedHashMap;

import com.github.jsonldjava.core.JsonLdError;

import info.weboftrust.ldsignatures.LdSignature;
import info.weboftrust.ldsignatures.suites.SignatureSuite;
import info.weboftrust.ldsignatures.suites.SignatureSuites;
import info.weboftrust.ldsignatures.util.CanonicalizationUtil;

public abstract class LdValidator <SIGNATURESUITE extends SignatureSuite> {

	protected SIGNATURESUITE signatureSuite;

	protected LdValidator(SIGNATURESUITE signatureSuite) {

		this.signatureSuite = signatureSuite;
	}

	public static LdValidator<? extends SignatureSuite> ldValidatorForSignatureSuite(String signatureSuite) {

		if (SignatureSuites.SIGNATURE_SUITE_RSASIGNATURE2017.getTerm().equals(signatureSuite)) return new RsaSignature2017LdValidator();
		if (SignatureSuites.SIGNATURE_SUITE_ED25519SIGNATURE2018.getTerm().equals(signatureSuite)) return new Ed25519Signature2018LdValidator();
		if (SignatureSuites.SIGNATURE_SUITE_ECDSAKOBLITZSIGNATURE2016.getTerm().equals(signatureSuite)) return new EcdsaKoblitzSignature2016LdValidator();

		throw new IllegalArgumentException();
	}

	public abstract boolean validate(String canonicalizedDocument, LdSignature ldSignature) throws GeneralSecurityException;

	public boolean validate(LinkedHashMap<String, Object> jsonLdObject, LdSignature ldSignature) throws JsonLdError, GeneralSecurityException {

		// obtain the canonicalized document

		LinkedHashMap<String, Object> jsonLdObjectWithoutSignature = new LinkedHashMap<String, Object> (jsonLdObject);
		LdSignature.removeFromJsonLdObject(jsonLdObjectWithoutSignature);
		String canonicalizedDocument = CanonicalizationUtil.buildCanonicalizedDocument(jsonLdObjectWithoutSignature);

		// validate

		boolean validate = this.validate(canonicalizedDocument, ldSignature);

		// done

		return validate;
	}

	public boolean validate(LinkedHashMap<String, Object> jsonLdObject) throws JsonLdError, GeneralSecurityException {

		// obtain the signature object

		LdSignature ldSignature = LdSignature.getFromJsonLdObject(jsonLdObject);
		if (ldSignature == null) return false;

		// done

		return this.validate(jsonLdObject, ldSignature);
	}
}
