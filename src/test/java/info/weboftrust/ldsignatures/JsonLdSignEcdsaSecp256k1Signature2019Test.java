package info.weboftrust.ldsignatures;

import foundation.identity.jsonld.JsonLDObject;
import foundation.identity.jsonld.JsonLDUtils;
import info.weboftrust.ldsignatures.jsonld.LDSecurityContexts;
import info.weboftrust.ldsignatures.signer.EcdsaSecp256k1Signature2019LdSigner;
import info.weboftrust.ldsignatures.suites.SignatureSuites;
import info.weboftrust.ldsignatures.verifier.EcdsaSecp256k1Signature2019LdVerifier;
import org.junit.jupiter.api.Test;

import java.io.InputStreamReader;
import java.net.URI;
import java.util.Date;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class JsonLdSignEcdsaSecp256k1Signature2019Test {

	@Test
	@SuppressWarnings("unchecked")
	public void testSignEcdsaSecp256k1Signature2019() throws Throwable {

		JsonLDObject jsonLdObject = JsonLDObject.fromJson(new InputStreamReader(JsonLdSignEcdsaSecp256k1Signature2019Test.class.getResourceAsStream("input.jsonld")));
		jsonLdObject.setDocumentLoader(LDSecurityContexts.DOCUMENT_LOADER);

		URI creator = URI.create("did:sov:WRfXPg8dantKVubE3HX8pw");
		Date created = JsonLDUtils.DATE_FORMAT.parse("2017-10-24T05:33:31Z");
		String domain = "example.com";
		String nonce = null;

		EcdsaSecp256k1Signature2019LdSigner signer = new EcdsaSecp256k1Signature2019LdSigner(TestUtil.testSecp256k1PrivateKey);
		signer.setCreator(creator);
		signer.setCreated(created);
		signer.setDomain(domain);
		signer.setNonce(nonce);
		LdProof ldProof = signer.sign(jsonLdObject);

		assertEquals(SignatureSuites.SIGNATURE_SUITE_ECDSASECP256L1SIGNATURE2019.getTerm(), ldProof.getType());
		assertEquals(creator, ldProof.getCreator());
		assertEquals(created, ldProof.getCreated());
		assertEquals(domain, ldProof.getDomain());
		assertEquals(nonce, ldProof.getNonce());
		assertEquals("eyJiNjQiOmZhbHNlLCJjcml0IjpbImI2NCJdLCJhbGciOiJFUzI1NksifQ..MEUCIQC3t0NSkMxEAGwLjhhE-G__-Ok5CZGcT9GBbKqVvozh-AIgBg6mqSDiJoKcK6aLN88Gorlb8qR-yv9VtDfUM9qQZUY", ldProof.getJws());

		EcdsaSecp256k1Signature2019LdVerifier verifier = new EcdsaSecp256k1Signature2019LdVerifier(TestUtil.testSecp256k1PublicKey);
		boolean verify = verifier.verify(jsonLdObject, ldProof);
		assertTrue(verify);
	}
}
