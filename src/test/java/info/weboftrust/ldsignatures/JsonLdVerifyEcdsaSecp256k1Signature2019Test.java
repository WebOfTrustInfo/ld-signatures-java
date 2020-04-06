package info.weboftrust.ldsignatures;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.LinkedHashMap;

import org.junit.jupiter.api.Test;

import com.github.jsonldjava.utils.JsonUtils;

import info.weboftrust.ldsignatures.verifier.EcdsaSecp256k1Signature2019LdVerifier;

public class JsonLdVerifyEcdsaSecp256k1Signature2019Test {

	@Test
	@SuppressWarnings("unchecked")
	public void testVerify() throws Exception {

		LinkedHashMap<String, Object> jsonLdObject = (LinkedHashMap<String, Object>) JsonUtils.fromInputStream(JsonLdVerifyEcdsaSecp256k1Signature2019Test.class.getResourceAsStream("signed.secp256k1.jsonld"));

		EcdsaSecp256k1Signature2019LdVerifier verifier = new EcdsaSecp256k1Signature2019LdVerifier(TestUtil.testSecp256k1PublicKey);
		boolean verify = verifier.verify(jsonLdObject);

		assertTrue(verify);
	}

	@SuppressWarnings("unchecked")
	public void testBadVerify() throws Exception {

		LinkedHashMap<String, Object> jsonLdObject = (LinkedHashMap<String, Object>) JsonUtils.fromInputStream(JsonLdVerifyEcdsaSecp256k1Signature2019Test.class.getResourceAsStream("signed.secp256k1.bad.jsonld"));

		EcdsaSecp256k1Signature2019LdVerifier verifier = new EcdsaSecp256k1Signature2019LdVerifier(TestUtil.testSecp256k1PublicKey);
		boolean verify = verifier.verify(jsonLdObject);

		assertFalse(verify);
	}
}
