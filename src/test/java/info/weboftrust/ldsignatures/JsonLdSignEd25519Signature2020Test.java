package info.weboftrust.ldsignatures;

import com.danubetech.keyformats.crypto.provider.Ed25519Provider;
import com.danubetech.keyformats.crypto.provider.RandomProvider;
import com.danubetech.keyformats.crypto.provider.SHA256Provider;
import com.danubetech.keyformats.crypto.provider.impl.JavaRandomProvider;
import com.danubetech.keyformats.crypto.provider.impl.JavaSHA256Provider;
import com.danubetech.keyformats.crypto.provider.impl.TinkEd25519Provider;
import foundation.identity.jsonld.JsonLDObject;
import foundation.identity.jsonld.JsonLDUtils;
import info.weboftrust.ldsignatures.jsonld.LDSecurityContexts;
import info.weboftrust.ldsignatures.signer.Ed25519Signature2020LdSigner;
import info.weboftrust.ldsignatures.suites.SignatureSuites;
import info.weboftrust.ldsignatures.verifier.Ed25519Signature2020LdVerifier;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.InputStreamReader;
import java.net.URI;
import java.util.Date;
import java.util.Objects;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class JsonLdSignEd25519Signature2020Test {

	@BeforeEach
	public void before() {

		RandomProvider.set(new JavaRandomProvider());
		SHA256Provider.set(new JavaSHA256Provider());
		Ed25519Provider.set(new TinkEd25519Provider());
	}

	@Test
	@SuppressWarnings("unchecked")
	public void testSign() throws Throwable {

		JsonLDObject jsonLdObject = JsonLDObject.fromJson(new InputStreamReader(Objects.requireNonNull(JsonLdSignEd25519Signature2020Test.class.getResourceAsStream("input.jsonld"))));
		jsonLdObject.setDocumentLoader(LDSecurityContexts.DOCUMENT_LOADER);

		URI creator = URI.create("did:sov:WRfXPg8dantKVubE3HX8pw");
		Date created = JsonLDUtils.DATE_FORMAT.parse("2017-10-24T05:33:31Z");
		String domain = "example.com";
		String nonce = null;

		Ed25519Signature2020LdSigner signer = new Ed25519Signature2020LdSigner(TestUtil.testEd25519PrivateKey);
		signer.setCreator(creator);
		signer.setCreated(created);
		signer.setDomain(domain);
		signer.setNonce(nonce);
		LdProof ldProof = signer.sign(jsonLdObject);

		assertEquals(SignatureSuites.SIGNATURE_SUITE_ED25519SIGNATURE2020.getTerm(), ldProof.getType());
		assertEquals(creator, ldProof.getCreator());
		assertEquals(created, ldProof.getCreated());
		assertEquals(domain, ldProof.getDomain());
		assertEquals(nonce, ldProof.getNonce());
		assertEquals("zd4XJsrXZPKR4KyYfHYTXZwHdcetercr5apNMgh5rjPp9nobNmCrtXFn5eiDMzXz7nSfYuhMhmKnPph1Epfi5FuT", ldProof.getProofValue());

		Ed25519Signature2020LdVerifier verifier = new Ed25519Signature2020LdVerifier(TestUtil.testEd25519PublicKey);
		boolean verify = verifier.verify(jsonLdObject, ldProof);
		assertTrue(verify);
	}
}
