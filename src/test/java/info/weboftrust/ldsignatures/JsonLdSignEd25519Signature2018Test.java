package info.weboftrust.ldsignatures;

import java.net.URI;
import java.util.LinkedHashMap;

import com.github.jsonldjava.utils.JsonUtils;

import info.weboftrust.ldsignatures.signer.Ed25519Signature2018LdSigner;
import info.weboftrust.ldsignatures.suites.SignatureSuites;
import info.weboftrust.ldsignatures.validator.Ed25519Signature2018LdValidator;
import junit.framework.TestCase;

public class JsonLdSignEd25519Signature2018Test extends TestCase {

	@SuppressWarnings("unchecked")
	public void testSignEd25519Signature2018() throws Exception {

		LinkedHashMap<String, Object> jsonLdObject = (LinkedHashMap<String, Object>) JsonUtils.fromInputStream(JsonLdSignEd25519Signature2018Test.class.getResourceAsStream("input.jsonld"));

		URI creator = URI.create("https://example.com/jdoe/keys/1");
		String created = "2017-10-24T05:33:31Z";
		String domain = "example.com";
		String nonce = null;

		Ed25519Signature2018LdSigner signer = new Ed25519Signature2018LdSigner(creator, created, domain, nonce, TestUtil.testEd25519PrivateKey);
		LdSignature ldSignature = signer.sign(jsonLdObject);

		assertEquals(SignatureSuites.SIGNATURE_SUITE_ED25519SIGNATURE2018.getTerm(), ldSignature.getType());
		assertEquals(creator, ldSignature.getCreator());
		assertEquals(created, ldSignature.getCreated());
		assertEquals(domain, ldSignature.getDomain());
		assertEquals(nonce, ldSignature.getNonce());
		assertEquals("if8ooA+32YZc4SQBvIDDY9tgTatPoq4IZ8Kr+We1t38LR2RuURmaVu9D4shbi4VvND87PUqq5/0vsNFEGIIEDA==", ldSignature.getSignatureValue());

		Ed25519Signature2018LdValidator validator = new Ed25519Signature2018LdValidator(TestUtil.testEd25519PublicKey);
		boolean validate = validator.validate(jsonLdObject, ldSignature);
		assertTrue(validate);
	}
}
