package info.weboftrust.ldsignatures;

import foundation.identity.jsonld.JsonLDObject;
import info.weboftrust.ldsignatures.jsonld.LDSecurityContexts;
import info.weboftrust.ldsignatures.verifier.JcsEcdsaSecp256k1Signature2019LdVerifier;
import org.junit.jupiter.api.Test;

import java.io.InputStreamReader;
import java.util.Objects;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class JsonLdVerifyJcsEcdsaSecp256k1Signature2019Test {

	@Test
	@SuppressWarnings("unchecked")
	public void testVerify() throws Throwable {

		JsonLDObject jsonLdObject = JsonLDObject.fromJson(new InputStreamReader(Objects.requireNonNull(JsonLdVerifyJcsEcdsaSecp256k1Signature2019Test.class.getResourceAsStream("signed.good.JcsEcdsaSecp256k1Signature2019.jsonld"))));
		jsonLdObject.setDocumentLoader(LDSecurityContexts.DOCUMENT_LOADER);

		JcsEcdsaSecp256k1Signature2019LdVerifier verifier = new JcsEcdsaSecp256k1Signature2019LdVerifier(TestUtil.testSecp256k1PublicKey);
		boolean verify = verifier.verify(jsonLdObject);

		assertTrue(verify);
	}

	@Test
	@SuppressWarnings("unchecked")
	public void testBadVerify() throws Throwable {

		JsonLDObject jsonLdObject = JsonLDObject.fromJson(new InputStreamReader(Objects.requireNonNull(JsonLdVerifyJcsEcdsaSecp256k1Signature2019Test.class.getResourceAsStream("signed.bad.JcsEcdsaSecp256k1Signature2019.jsonld"))));
		jsonLdObject.setDocumentLoader(LDSecurityContexts.DOCUMENT_LOADER);

		JcsEcdsaSecp256k1Signature2019LdVerifier verifier = new JcsEcdsaSecp256k1Signature2019LdVerifier(TestUtil.testSecp256k1PublicKey);
		boolean verify = verifier.verify(jsonLdObject);

		assertFalse(verify);
	}
}
