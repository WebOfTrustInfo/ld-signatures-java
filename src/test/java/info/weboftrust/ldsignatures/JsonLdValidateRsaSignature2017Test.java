package info.weboftrust.ldsignatures;

import java.util.LinkedHashMap;

import com.github.jsonldjava.utils.JsonUtils;

import info.weboftrust.ldsignatures.validator.RsaSignature2017LdValidator;
import junit.framework.TestCase;

public class JsonLdValidateRsaSignature2017Test extends TestCase {

	@SuppressWarnings("unchecked")
	public void testValidate() throws Exception {

		LinkedHashMap<String, Object> jsonLdObject = (LinkedHashMap<String, Object>) JsonUtils.fromInputStream(JsonLdValidateRsaSignature2017Test.class.getResourceAsStream("signed.rsa.jsonld"));

		RsaSignature2017LdValidator validator = new RsaSignature2017LdValidator(TestUtil.testRSAPublicKey);
		boolean validate = validator.validate(jsonLdObject);

		assertTrue(validate);
	}

	@SuppressWarnings("unchecked")
	public void testBadValidate() throws Exception {

		LinkedHashMap<String, Object> jsonLdObject = (LinkedHashMap<String, Object>) JsonUtils.fromInputStream(JsonLdValidateRsaSignature2017Test.class.getResourceAsStream("signed.rsa.bad.jsonld"));

		RsaSignature2017LdValidator validator = new RsaSignature2017LdValidator(TestUtil.testRSAPublicKey);
		boolean validate = validator.validate(jsonLdObject);

		assertFalse(validate);
	}
}
