package info.weboftrust.ldsignatures;

import java.util.LinkedHashMap;

import com.github.jsonldjava.utils.JsonUtils;

import info.weboftrust.ldsignatures.validator.Ed25519Signature2018LdValidator;
import junit.framework.TestCase;

public class JsonLdValidateEd25519Signature2018Test extends TestCase {

	@SuppressWarnings("unchecked")
	public void testValidate() throws Exception {

		LinkedHashMap<String, Object> jsonLdObject = (LinkedHashMap<String, Object>) JsonUtils.fromInputStream(JsonLdValidateEd25519Signature2018Test.class.getResourceAsStream("signed.ed25519.jsonld"));

		Ed25519Signature2018LdValidator validator = new Ed25519Signature2018LdValidator(TestUtil.testEd25519PublicKey);
		boolean validate = validator.validate(jsonLdObject);

		assertTrue(validate);
	}

	@SuppressWarnings("unchecked")
	public void testBadValidate() throws Exception {

		LinkedHashMap<String, Object> jsonLdObject = (LinkedHashMap<String, Object>) JsonUtils.fromInputStream(JsonLdValidateEd25519Signature2018Test.class.getResourceAsStream("signed.ed25519.bad.jsonld"));

		Ed25519Signature2018LdValidator validator = new Ed25519Signature2018LdValidator(TestUtil.testEd25519PublicKey);
		boolean validate = validator.validate(jsonLdObject);

		assertFalse(validate);
	}
}
