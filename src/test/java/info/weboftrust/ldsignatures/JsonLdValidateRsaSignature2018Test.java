package info.weboftrust.ldsignatures;

import java.util.LinkedHashMap;

import com.github.jsonldjava.utils.JsonUtils;

import info.weboftrust.ldsignatures.validator.RsaSignature2018LdValidator;
import junit.framework.TestCase;

public class JsonLdValidateRsaSignature2018Test extends TestCase {

	@SuppressWarnings("unchecked")
	public void testValidate() throws Exception {

		LinkedHashMap<String, Object> jsonLdObject = (LinkedHashMap<String, Object>) JsonUtils.fromInputStream(JsonLdValidateRsaSignature2018Test.class.getResourceAsStream("signed.rsa.jsonld"));

		RsaSignature2018LdValidator validator = new RsaSignature2018LdValidator(TestUtil.testRSAPublicKey);
		boolean validate = validator.validate(jsonLdObject);

		assertTrue(validate);
	}

	@SuppressWarnings("unchecked")
	public void testBadValidate() throws Exception {

		LinkedHashMap<String, Object> jsonLdObject = (LinkedHashMap<String, Object>) JsonUtils.fromInputStream(JsonLdValidateRsaSignature2018Test.class.getResourceAsStream("signed.rsa.bad.jsonld"));

		RsaSignature2018LdValidator validator = new RsaSignature2018LdValidator(TestUtil.testRSAPublicKey);
		boolean validate = validator.validate(jsonLdObject);

		assertFalse(validate);
	}
}
