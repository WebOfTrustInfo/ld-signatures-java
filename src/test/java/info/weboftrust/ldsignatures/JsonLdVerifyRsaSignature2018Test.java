package info.weboftrust.ldsignatures;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.LinkedHashMap;

import org.junit.jupiter.api.Test;

import com.github.jsonldjava.utils.JsonUtils;

import info.weboftrust.ldsignatures.verifier.RsaSignature2018LdVerifier;

public class JsonLdVerifyRsaSignature2018Test {

	@Test
	@SuppressWarnings("unchecked")
	public void testVerify() throws Exception {

		LinkedHashMap<String, Object> jsonLdObject = (LinkedHashMap<String, Object>) JsonUtils.fromInputStream(JsonLdVerifyRsaSignature2018Test.class.getResourceAsStream("signed.rsa.jsonld"));

		RsaSignature2018LdVerifier verifier = new RsaSignature2018LdVerifier(TestUtil.testRSAPublicKey);
		boolean verify = verifier.verify(jsonLdObject);

		assertTrue(verify);
	}

	@SuppressWarnings("unchecked")
	public void testBadVerify() throws Exception {

		LinkedHashMap<String, Object> jsonLdObject = (LinkedHashMap<String, Object>) JsonUtils.fromInputStream(JsonLdVerifyRsaSignature2018Test.class.getResourceAsStream("signed.rsa.bad.jsonld"));

		RsaSignature2018LdVerifier verifier = new RsaSignature2018LdVerifier(TestUtil.testRSAPublicKey);
		boolean verify = verifier.verify(jsonLdObject);

		assertFalse(verify);
	}
}
