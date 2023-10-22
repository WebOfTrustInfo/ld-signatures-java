package info.weboftrust.ldsignatures;

import com.danubetech.keyformats.crypto.provider.Ed25519Provider;
import com.danubetech.keyformats.crypto.provider.RandomProvider;
import com.danubetech.keyformats.crypto.provider.SHA256Provider;
import com.danubetech.keyformats.crypto.provider.impl.JavaRandomProvider;
import com.danubetech.keyformats.crypto.provider.impl.JavaSHA256Provider;
import com.danubetech.keyformats.crypto.provider.impl.TinkEd25519Provider;
import foundation.identity.jsonld.JsonLDObject;
import info.weboftrust.ldsignatures.jsonld.LDSecurityContexts;
import info.weboftrust.ldsignatures.verifier.JcsEd25519Signature2020LdVerifier;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.InputStreamReader;
import java.util.Objects;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class JsonLdVerifyJcsEd25519Signature2020Test {

	@BeforeEach
	public void before() {

		RandomProvider.set(new JavaRandomProvider());
		SHA256Provider.set(new JavaSHA256Provider());
		Ed25519Provider.set(new TinkEd25519Provider());
	}

	@Test
	@SuppressWarnings("unchecked")
	public void testVerify() throws Throwable {

		JsonLDObject jsonLdObject = JsonLDObject.fromJson(new InputStreamReader(Objects.requireNonNull(JsonLdVerifyJcsEd25519Signature2020Test.class.getResourceAsStream("signed.good.JcsEd25519Signature2020.jsonld"))));
		jsonLdObject.setDocumentLoader(LDSecurityContexts.DOCUMENT_LOADER);

		JcsEd25519Signature2020LdVerifier verifier = new JcsEd25519Signature2020LdVerifier(TestUtil.testEd25519PublicKey);
		boolean verify = verifier.verify(jsonLdObject);
		assertTrue(verify);
	}

	@Test
	@SuppressWarnings("unchecked")
	public void testBadVerify() throws Throwable {

		JsonLDObject jsonLdObject = JsonLDObject.fromJson(new InputStreamReader(Objects.requireNonNull(JsonLdVerifyJcsEd25519Signature2020Test.class.getResourceAsStream("signed.bad.JcsEd25519Signature2020.jsonld"))));
		jsonLdObject.setDocumentLoader(LDSecurityContexts.DOCUMENT_LOADER);

		JcsEd25519Signature2020LdVerifier verifier = new JcsEd25519Signature2020LdVerifier(TestUtil.testEd25519PublicKey);
		boolean verify = verifier.verify(jsonLdObject);
		assertFalse(verify);
	}
}
