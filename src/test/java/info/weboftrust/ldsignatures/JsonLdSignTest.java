package info.weboftrust.ldsignatures;

import java.net.URI;
import java.util.LinkedHashMap;

import com.github.jsonldjava.utils.JsonUtils;

import info.weboftrust.ldsignatures.signer.RsaSignature2017LdSigner;
import info.weboftrust.ldsignatures.suites.SignatureSuites;
import junit.framework.TestCase;

public class JsonLdSignTest extends TestCase {

	@Override
	protected void setUp() throws Exception {

	}

	@Override
	protected void tearDown() throws Exception {

	}

	@SuppressWarnings("unchecked")
	public void testSign() throws Exception {

		LinkedHashMap<String, Object> jsonLdObject = (LinkedHashMap<String, Object>) JsonUtils.fromString(TestUtil.read(JsonLdSignTest.class.getResourceAsStream("sign.test.jsonld")));
		URI creator = URI.create("https://example.com/jdoe/keys/1");
		String created = "2017-10-24T05:33:31Z";
		String domain = "example.com";
		String nonce = null;

		RsaSignature2017LdSigner signer = new RsaSignature2017LdSigner(creator, created, domain, nonce, TestUtil.testRSAPrivateKey);
		LdSignature ldSignature = signer.sign(jsonLdObject);

		assertEquals(SignatureSuites.SIGNATURE_SUITE_RSASIGNATURE2017.getTerm(), ldSignature.getType());
		assertEquals(creator, ldSignature.getCreator());
		assertEquals(created, ldSignature.getCreated());
		assertEquals(domain, ldSignature.getDomain());
		assertEquals(nonce, ldSignature.getNonce());
		assertEquals("eyJhbGciOiJSUzI1NiIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..d8wWxUJTpxAbYHLgFfaYYJJHdWido6wDMBeUhPL7e0m4vuj7xUePbnorf-YqlGZwaGI0zVI_-qJmGbqSB0bm8x20Z9nvawZS8lTk_4uLIPwSPeH8Cyu5bdUP1OIImBhm0gpUmAZfnDVhCgC81lJOaa4tqCjSr940cRUQ9agYjcOyhUBdBOwQgjd8jgkI7vmXqs2m7TmOVY7aAr-6X3AhJqX_a-iD5sdBsoTNulfTyPjEZcFXMvs6gx2078ftwYiUNQzV4qKwkhmUSAINWomKe_fUh4BpdPbsZax7iKYG1hSWRkmrd9R8FllotKQ_nMWZv0urn02F83US62F6ORRT0w", ldSignature.getSignatureValue());
	}
}
