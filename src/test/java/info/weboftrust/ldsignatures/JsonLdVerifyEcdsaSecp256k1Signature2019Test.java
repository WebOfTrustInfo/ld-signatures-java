package info.weboftrust.ldsignatures;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.InputStreamReader;

import foundation.identity.jsonld.JsonLDObject;
import org.junit.jupiter.api.Test;

import info.weboftrust.ldsignatures.verifier.EcdsaSecp256k1Signature2019LdVerifier;

public class JsonLdVerifyEcdsaSecp256k1Signature2019Test {

	@Test
	@SuppressWarnings("unchecked")
	public void testVerify() throws Throwable {

		JsonLDObject jsonLdObject = JsonLDObject.fromJson(new InputStreamReader(JsonLdVerifyEcdsaSecp256k1Signature2019Test.class.getResourceAsStream("signed.good.secp256k1.jsonld")));

		EcdsaSecp256k1Signature2019LdVerifier verifier = new EcdsaSecp256k1Signature2019LdVerifier(TestUtil.testSecp256k1PublicKey);
		boolean verify = verifier.verify(jsonLdObject);

		assertTrue(verify);
	}

	@Test
	@SuppressWarnings("unchecked")
	public void testBadVerify() throws Throwable {

		JsonLDObject jsonLdObject = JsonLDObject.fromJson(new InputStreamReader(JsonLdVerifyEcdsaSecp256k1Signature2019Test.class.getResourceAsStream("signed.bad.secp256k1.jsonld")));

		EcdsaSecp256k1Signature2019LdVerifier verifier = new EcdsaSecp256k1Signature2019LdVerifier(TestUtil.testSecp256k1PublicKey);
		boolean verify = verifier.verify(jsonLdObject);

		assertFalse(verify);
	}
}
