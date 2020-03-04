package info.weboftrust.ldsignatures;

import java.net.URI;
import java.util.LinkedHashMap;

import com.github.jsonldjava.utils.JsonUtils;

import info.weboftrust.ldsignatures.signer.RsaSignature2018LdSigner;
import info.weboftrust.ldsignatures.suites.SignatureSuites;
import info.weboftrust.ldsignatures.verifier.RsaSignature2018LdVerifier;
import junit.framework.TestCase;

public class JsonLdSignRsaSignature2018Test extends TestCase {

	@SuppressWarnings("unchecked")
	public void testSignEd25519Signature2018() throws Exception {

		LinkedHashMap<String, Object> jsonLdObject = (LinkedHashMap<String, Object>) JsonUtils.fromInputStream(JsonLdSignRsaSignature2018Test.class.getResourceAsStream("input.jsonld"));

		URI creator = URI.create("https://example.com/jdoe/keys/1");
		String created = "2017-10-24T05:33:31Z";
		String domain = "example.com";
		String nonce = null;

		RsaSignature2018LdSigner signer = new RsaSignature2018LdSigner(TestUtil.testRSAPrivateKey);
		signer.setCreator(creator);
		signer.setCreated(created);
		signer.setDomain(domain);
		signer.setNonce(nonce);
		LdSignature ldSignature = signer.sign(jsonLdObject);

		assertEquals(SignatureSuites.SIGNATURE_SUITE_RSASIGNATURE2018.getTerm(), ldSignature.getType());
		assertEquals(creator, ldSignature.getCreator());
		assertEquals(created, ldSignature.getCreated());
		assertEquals(domain, ldSignature.getDomain());
		assertEquals(nonce, ldSignature.getNonce());
		assertEquals("eyJjcml0IjpbImI2NCJdLCJiNjQiOmZhbHNlLCJhbGciOiJSUzI1NiJ9..Gr0tgKv6_xyvUeaoP2SFXmP1iOnU5Y3PxwGE58onOdLeHKu_6voUfv2sWiC2dplbFBIkALMpdFdW-2CE63TARv8djEZ6cu1cOaqercrNH1tMzk3xDBWskP70AQOCbhz8VpmF0o5iekgd7troNkxrMrYGS1EkFV9VqToySzQY3tWS9NpHYutE4KlaKq6ZKsfdHCUgmK-PmifgMcQJAK8vx8sPLDmln3nvz0pZl6lGYFwBaoXOiaK_6coZot9W413lo9jxOVpzj6jxW0zdxjwX5DzpRkhw7Dj3r-vSpbDi9ec7sM3LKiZsOT2S7QAOJ9UK6LzZXPbBxFDuWwEMJnvKkQ", ldSignature.getJws());

		RsaSignature2018LdVerifier verifier = new RsaSignature2018LdVerifier(TestUtil.testRSAPublicKey);
		boolean verify = verifier.verify(jsonLdObject, ldSignature);
		assertTrue(verify);
	}
}
