package info.weboftrust.ldsignatures;

import java.net.URI;
import java.util.Date;
import java.util.LinkedHashMap;

import com.github.jsonldjava.utils.JsonUtils;

import info.weboftrust.ldsignatures.signer.EcdsaSecp256k1Signature2019LdSigner;
import info.weboftrust.ldsignatures.suites.SignatureSuites;
import info.weboftrust.ldsignatures.verifier.EcdsaSecp256k1Signature2019LdVerifier;
import junit.framework.TestCase;

public class JsonLdSignEcdsaSecp256k1Signature2019Test extends TestCase {

	@SuppressWarnings("unchecked")
	public void testSignEcdsaSecp256k1Signature2019() throws Exception {

		LinkedHashMap<String, Object> jsonLdObject = (LinkedHashMap<String, Object>) JsonUtils.fromInputStream(JsonLdSignEcdsaSecp256k1Signature2019Test.class.getResourceAsStream("input.jsonld"));

		URI creator = URI.create("did:sov:WRfXPg8dantKVubE3HX8pw");
		Date created = LdSignature.DATE_FORMAT.parse("2017-10-24T05:33:31Z");
		String domain = "example.com";
		String nonce = null;

		EcdsaSecp256k1Signature2019LdSigner signer = new EcdsaSecp256k1Signature2019LdSigner(TestUtil.testSecp256k1PrivateKey);
		signer.setCreator(creator);
		signer.setCreated(created);
		signer.setDomain(domain);
		signer.setNonce(nonce);
		LdSignature ldSignature = signer.sign(jsonLdObject);

		assertEquals(SignatureSuites.SIGNATURE_SUITE_ECDSASECP256L1SIGNATURE2019.getTerm(), ldSignature.getType());
		assertEquals(creator, ldSignature.getCreator());
		assertEquals(created, ldSignature.getCreated());
		assertEquals(domain, ldSignature.getDomain());
		assertEquals(nonce, ldSignature.getNonce());
		assertEquals("eyJjcml0IjpbImI2NCJdLCJiNjQiOmZhbHNlLCJhbGciOiJFUzI1NksifQ..MEQCIBB3xgG8ClzUR_NmKb3wiiGrr3051QruS14hFIpgXFRwAiB8AMwGJg66Tw07HNPonK36YjOVNDzAW7PLzrgZPc9oEA", ldSignature.getJws());

		EcdsaSecp256k1Signature2019LdVerifier verifier = new EcdsaSecp256k1Signature2019LdVerifier(TestUtil.testSecp256k1PublicKey);
		boolean verify = verifier.verify(jsonLdObject, ldSignature);
		assertTrue(verify);
	}
}
