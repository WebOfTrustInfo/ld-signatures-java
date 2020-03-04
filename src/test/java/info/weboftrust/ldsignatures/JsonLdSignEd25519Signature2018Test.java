package info.weboftrust.ldsignatures;

import java.net.URI;
import java.util.LinkedHashMap;

import com.github.jsonldjava.utils.JsonUtils;

import info.weboftrust.ldsignatures.signer.Ed25519Signature2018LdSigner;
import info.weboftrust.ldsignatures.suites.SignatureSuites;
import info.weboftrust.ldsignatures.verifier.Ed25519Signature2018LdVerifier;
import junit.framework.TestCase;

public class JsonLdSignEd25519Signature2018Test extends TestCase {

	@SuppressWarnings("unchecked")
	public void testSignEd25519Signature2018() throws Exception {

		LinkedHashMap<String, Object> jsonLdObject = (LinkedHashMap<String, Object>) JsonUtils.fromInputStream(JsonLdSignEd25519Signature2018Test.class.getResourceAsStream("input.jsonld"));

		URI creator = URI.create("did:sov:WRfXPg8dantKVubE3HX8pw");
		String created = "2017-10-24T05:33:31Z";
		String domain = "example.com";
		String nonce = null;

		Ed25519Signature2018LdSigner signer = new Ed25519Signature2018LdSigner(TestUtil.testEd25519PrivateKey);
		signer.setCreator(creator);
		signer.setCreated(created);
		signer.setDomain(domain);
		signer.setNonce(nonce);
		LdSignature ldSignature = signer.sign(jsonLdObject);

		assertEquals(SignatureSuites.SIGNATURE_SUITE_ED25519SIGNATURE2018.getTerm(), ldSignature.getType());
		assertEquals(creator, ldSignature.getCreator());
		assertEquals(created, ldSignature.getCreated());
		assertEquals(domain, ldSignature.getDomain());
		assertEquals(nonce, ldSignature.getNonce());
		assertEquals("eyJjcml0IjpbImI2NCJdLCJiNjQiOmZhbHNlLCJhbGciOiJFZERTQSJ9..xuj9osgec5or-U1x0gSXuaqE5MgJdBnBVueKw2w_JDRu4kt5BURAJwbyxtuV5Sfu3W1duTAUIczmaqRtWjbyCg", ldSignature.getJws());

		Ed25519Signature2018LdVerifier verifier = new Ed25519Signature2018LdVerifier(TestUtil.testEd25519PublicKey);
		boolean verify = verifier.verify(jsonLdObject, ldSignature);
		assertTrue(verify);
	}
}
