package info.weboftrust.ldsignatures;

import java.io.InputStreamReader;

import foundation.identity.jsonld.JsonLDObject;
import org.junit.jupiter.api.Test;

import info.weboftrust.ldsignatures.verifier.Ed25519Signature2018LdVerifier;
import static org.junit.jupiter.api.Assertions.*;

public class JsonLdVerifyEd25519Signature2018Test {

	@Test
	@SuppressWarnings("unchecked")
	public void testVerify() throws Throwable {

		JsonLDObject jsonLdObject = JsonLDObject.fromJson(new InputStreamReader(JsonLdVerifyEd25519Signature2018Test.class.getResourceAsStream("signed.good.ed25519.jsonld")));

		Ed25519Signature2018LdVerifier verifier = new Ed25519Signature2018LdVerifier(TestUtil.testEd25519PublicKey);
		boolean verify = verifier.verify(jsonLdObject);
		assertTrue(verify);
	}

	@Test
	@SuppressWarnings("unchecked")
	public void testBadVerify() throws Throwable {

		JsonLDObject jsonLdObject = JsonLDObject.fromJson(new InputStreamReader(JsonLdVerifyEd25519Signature2018Test.class.getResourceAsStream("signed.bad.ed25519.jsonld")));

		Ed25519Signature2018LdVerifier verifier = new Ed25519Signature2018LdVerifier(TestUtil.testEd25519PublicKey);
		boolean verify = verifier.verify(jsonLdObject);
		assertFalse(verify);
	}
}
