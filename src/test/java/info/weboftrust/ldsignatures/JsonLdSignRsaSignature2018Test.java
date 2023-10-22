package info.weboftrust.ldsignatures;

import foundation.identity.jsonld.JsonLDObject;
import foundation.identity.jsonld.JsonLDUtils;
import info.weboftrust.ldsignatures.jsonld.LDSecurityContexts;
import info.weboftrust.ldsignatures.signer.RsaSignature2018LdSigner;
import info.weboftrust.ldsignatures.suites.SignatureSuites;
import info.weboftrust.ldsignatures.verifier.RsaSignature2018LdVerifier;
import org.junit.jupiter.api.Test;

import java.io.InputStreamReader;
import java.net.URI;
import java.util.Date;
import java.util.Objects;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class JsonLdSignRsaSignature2018Test {

	@Test
	@SuppressWarnings("unchecked")
	public void testSign() throws Throwable {

		JsonLDObject jsonLdObject = JsonLDObject.fromJson(new InputStreamReader(Objects.requireNonNull(JsonLdSignRsaSignature2018Test.class.getResourceAsStream("input.jsonld"))));
		jsonLdObject.setDocumentLoader(LDSecurityContexts.DOCUMENT_LOADER);

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
		assertEquals("eyJiNjQiOmZhbHNlLCJjcml0IjpbImI2NCJdLCJhbGciOiJSUzI1NiJ9..Re15jwVmt168oDUXs76hCX3shLHkaNvZNrLSxwDvyfTvkFvmxy3u9bdlFCKBOUqYQefu7AC1qMEFmOn5nHme5SIa9OlO8_7vnwFo7DHf2JJajI40JllkVNxQ4hIhjqceD8tS5_J6fpt0RkhpX6AWRMj5wB60JenL0oONcF0G5EWR_s1g4R8w8benOTNFT53TZGmku6QQib6fOEzqOo_SVJVvBZYhim8UEHcVNOc2iCre0eobnXrGWxhdL0sUiltb0apkyWveJAdJ9ENHK6ef8zZC3NlWZKK5QzMBjbKm_wMDbPOI3e7mWarihM7bqjTdrHHeOifWEK_Cx9iuWJMx_A", ldProof.getJws());

		RsaSignature2018LdVerifier verifier = new RsaSignature2018LdVerifier(TestUtil.testRSAPublicKey);
		boolean verify = verifier.verify(jsonLdObject, ldProof);
		assertTrue(verify);
	}
}
