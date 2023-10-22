package info.weboftrust.ldsignatures;

import foundation.identity.jsonld.JsonLDObject;
import foundation.identity.jsonld.JsonLDUtils;
import info.weboftrust.ldsignatures.jsonld.LDSecurityContexts;
import info.weboftrust.ldsignatures.signer.JcsEcdsaSecp256k1Signature2019LdSigner;
import info.weboftrust.ldsignatures.suites.SignatureSuites;
import info.weboftrust.ldsignatures.verifier.JcsEcdsaSecp256k1Signature2019LdVerifier;
import org.junit.jupiter.api.Test;

import java.io.InputStreamReader;
import java.net.URI;
import java.util.Date;
import java.util.Objects;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class JsonLdSignJcsEcdsaSecp256k1Signature2019Test {

	@Test
	@SuppressWarnings("unchecked")
	public void testSignEcdsaSecp256k1Signature2019() throws Throwable {

		JsonLDObject jsonLdObject = JsonLDObject.fromJson(new InputStreamReader(Objects.requireNonNull(JsonLdSignJcsEcdsaSecp256k1Signature2019Test.class.getResourceAsStream("input.jsonld"))));
		jsonLdObject.setDocumentLoader(LDSecurityContexts.DOCUMENT_LOADER);

		URI creator = URI.create("did:sov:WRfXPg8dantKVubE3HX8pw");
		Date created = JsonLDUtils.DATE_FORMAT.parse("2017-10-24T05:33:31Z");
		String domain = "example.com";
		String nonce = null;

		JcsEcdsaSecp256k1Signature2019LdSigner signer = new JcsEcdsaSecp256k1Signature2019LdSigner(TestUtil.testSecp256k1PrivateKey);
		signer.setCreator(creator);
		signer.setCreated(created);
		signer.setDomain(domain);
		signer.setNonce(nonce);
		LdProof ldProof = signer.sign(jsonLdObject);

		assertEquals(SignatureSuites.SIGNATURE_SUITE_JCSECDSASECP256L1SIGNATURE2019.getTerm(), ldProof.getType());
		assertEquals(creator, ldProof.getCreator());
		assertEquals(created, ldProof.getCreated());
		assertEquals(domain, ldProof.getDomain());
		assertEquals(nonce, ldProof.getNonce());
		assertEquals("3vkXU7PnnuWczC5ink3mays1yrdkUkZhwh4xgsx8f7fRHB8CZ9Nj77MuJeNbqSESLPAsJSq91XN9pFtueosyZJ7t", ldProof.getJsonObject().get("signatureValue"));

		JcsEcdsaSecp256k1Signature2019LdVerifier verifier = new JcsEcdsaSecp256k1Signature2019LdVerifier(TestUtil.testSecp256k1PublicKey);
		boolean verify = verifier.verify(jsonLdObject, ldProof);
		assertTrue(verify);
	}
}
