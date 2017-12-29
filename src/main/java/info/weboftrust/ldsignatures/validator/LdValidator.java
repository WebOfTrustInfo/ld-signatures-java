package info.weboftrust.ldsignatures.validator;

import java.util.LinkedHashMap;

import org.jose4j.lang.JoseException;

import com.github.jsonldjava.core.JsonLdError;

import info.weboftrust.ldsignatures.LdSignature;
import info.weboftrust.ldsignatures.suites.SignatureSuite;
import info.weboftrust.ldsignatures.util.CanonicalizationUtil;

public abstract class LdValidator <SIGNATURESUITE extends SignatureSuite> {

	protected SIGNATURESUITE signatureSuite;

	protected LdValidator(SIGNATURESUITE signatureSuite) {

		this.signatureSuite = signatureSuite;
	}

	public abstract boolean validate(String canonicalizedDocument, LdSignature ldSignature) throws JoseException;

	public boolean validate(LinkedHashMap<String, Object> jsonLdObject, LdSignature ldSignature) throws JsonLdError, JoseException {

		// obtain the canonicalized document

		LinkedHashMap<String, Object> jsonLdObjectWithoutSignature = new LinkedHashMap<String, Object> (jsonLdObject);
		LdSignature.removeFromJsonLdObject(jsonLdObjectWithoutSignature);
		String canonicalizedDocument = CanonicalizationUtil.buildCanonicalizedDocument(jsonLdObjectWithoutSignature);

		// validate

		boolean validate = this.validate(canonicalizedDocument, ldSignature);

		// done

		return validate;
	}

	public boolean validate(LinkedHashMap<String, Object> jsonLdObject) throws JsonLdError, JoseException {

		// obtain the signature object

		LdSignature ldSignature = LdSignature.getFromJsonLdObject(jsonLdObject);
		if (ldSignature == null) return false;

		// done

		return this.validate(jsonLdObject, ldSignature);
	}
}
