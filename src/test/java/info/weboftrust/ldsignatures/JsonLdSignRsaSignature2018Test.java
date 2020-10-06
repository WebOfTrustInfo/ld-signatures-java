package info.weboftrust.ldsignatures;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.InputStreamReader;
import java.net.URI;
import java.util.Date;

import foundation.identity.jsonld.JsonLDObject;
import foundation.identity.jsonld.JsonLDUtils;
import org.junit.jupiter.api.Test;

import info.weboftrust.ldsignatures.signer.RsaSignature2018LdSigner;
import info.weboftrust.ldsignatures.suites.SignatureSuites;
import info.weboftrust.ldsignatures.verifier.RsaSignature2018LdVerifier;

public class JsonLdSignRsaSignature2018Test {

	@Test
	@SuppressWarnings("unchecked")
	public void testSignEd25519Signature2018() throws Throwable {

		JsonLDObject jsonLdObject = JsonLDObject.fromJson(new InputStreamReader(JsonLdSignRsaSignature2018Test.class.getResourceAsStream("input.jsonld")));

		URI creator = URI.create("https://example.com/jdoe/keys/1");
		Date created = JsonLDUtils.DATE_FORMAT.parse("2017-10-24T05:33:31Z");
		String domain = "example.com";
		String nonce = null;

		RsaSignature2018LdSigner signer = new RsaSignature2018LdSigner(TestUtil.testRSAPrivateKey);
		signer.setCreator(creator);
		signer.setCreated(created);
		signer.setDomain(domain);
		signer.setNonce(nonce);
		LdProof ldProof = signer.sign(jsonLdObject);

		assertEquals(SignatureSuites.SIGNATURE_SUITE_RSASIGNATURE2018.getTerm(), ldProof.getType());
		assertEquals(creator, ldProof.getCreator());
		assertEquals(created, ldProof.getCreated());
		assertEquals(domain, ldProof.getDomain());
		assertEquals(nonce, ldProof.getNonce());
		assertEquals("eyJjcml0IjpbImI2NCJdLCJiNjQiOmZhbHNlLCJhbGciOiJSUzI1NiJ9..q7KR0217QFEUFF6q-vbCMcyBgANJCQCP9nCDPPbQHUSgOnnr7iN-8gil3FN2v-NNrBAxSh2J8WCZAttxYUahSosVPIFE6wPnvsaHtk1oLizMeitPthsle_Rvr8qwEagOzlQyP2NmDQsDiCOToQyqJ1rH6Cg3-chxgyitvZ2Odts4b9EW93zZuMMu3JQ_r0RNHVfmFGsTz-I9SCsrHePWHrrZH4eeVoGsRf4H8GSOQ_MC8hDH_EPNqGwqwNirO8qQve57rSfVqFCTDQwZAQP8U6pFApwSapTFIlG3oW6ULKOfwWsg3vi1btbgGBMI-1KGzOVt5MTfjdJVTw8SDIgJiA", ldProof.getJws());

		RsaSignature2018LdVerifier verifier = new RsaSignature2018LdVerifier(TestUtil.testRSAPublicKey);
		boolean verify = verifier.verify(jsonLdObject, ldProof);
		assertTrue(verify);
	}
}
