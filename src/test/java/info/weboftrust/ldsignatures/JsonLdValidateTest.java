package info.weboftrust.ldsignatures;

import java.util.LinkedHashMap;

import com.github.jsonldjava.utils.JsonUtils;

import info.weboftrust.ldsignatures.validator.RsaSignature2017LdValidator;
import junit.framework.TestCase;

public class JsonLdValidateTest extends TestCase {

	@Override
	protected void setUp() throws Exception {

	}

	@Override
	protected void tearDown() throws Exception {

	}

	@SuppressWarnings("unchecked")
	public void testValidate() throws Exception {

		LinkedHashMap<String, Object> jsonLdObject = (LinkedHashMap<String, Object>) JsonUtils.fromString(TestUtil.read(JsonLdValidateTest.class.getResourceAsStream("validate.test.jsonld")));

		RsaSignature2017LdValidator validator = new RsaSignature2017LdValidator(TestUtil.testRSAPublicKey);
		boolean validate = validator.validate(jsonLdObject);

		assertTrue(validate);
	}

	@SuppressWarnings("unchecked")
	public void testBadValidate() throws Exception {

		LinkedHashMap<String, Object> jsonLdObject = (LinkedHashMap<String, Object>) JsonUtils.fromString(TestUtil.read(JsonLdValidateTest.class.getResourceAsStream("validate.bad.test.jsonld")));

		RsaSignature2017LdValidator validator = new RsaSignature2017LdValidator(TestUtil.testRSAPublicKey);
		boolean validate = validator.validate(jsonLdObject);

		assertFalse(validate);
	}
}
