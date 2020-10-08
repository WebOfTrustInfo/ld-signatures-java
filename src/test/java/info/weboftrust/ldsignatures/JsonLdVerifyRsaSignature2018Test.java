package info.weboftrust.ldsignatures;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.InputStreamReader;

import foundation.identity.jsonld.JsonLDObject;
import org.junit.jupiter.api.Test;

import info.weboftrust.ldsignatures.verifier.RsaSignature2018LdVerifier;

public class JsonLdVerifyRsaSignature2018Test {

	@Test
	@SuppressWarnings("unchecked")
	public void testVerify() throws Throwable {

		JsonLDObject jsonLdObject = JsonLDObject.fromJson(new InputStreamReader(JsonLdVerifyRsaSignature2018Test.class.getResourceAsStream("signed.good.rsa.jsonld")));

		RsaSignature2018LdVerifier verifier = new RsaSignature2018LdVerifier(TestUtil.testRSAPublicKey);
		boolean verify = verifier.verify(jsonLdObject);

		assertTrue(verify);
	}

	@Test
	@SuppressWarnings("unchecked")
	public void testBadVerify() throws Throwable {

		JsonLDObject jsonLdObject = JsonLDObject.fromJson(new InputStreamReader(JsonLdVerifyRsaSignature2018Test.class.getResourceAsStream("signed.bad.rsa.jsonld")));

		RsaSignature2018LdVerifier verifier = new RsaSignature2018LdVerifier(TestUtil.testRSAPublicKey);
		boolean verify = verifier.verify(jsonLdObject);

		assertFalse(verify);
	}
}
