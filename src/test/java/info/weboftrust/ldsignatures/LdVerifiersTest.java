package info.weboftrust.ldsignatures;

import info.weboftrust.ldsignatures.verifier.EcdsaKoblitzSignature2016LdVerifier;
import info.weboftrust.ldsignatures.verifier.Ed25519Signature2018LdVerifier;
import info.weboftrust.ldsignatures.verifier.LdVerifier;
import info.weboftrust.ldsignatures.verifier.RsaSignature2018LdVerifier;
import junit.framework.TestCase;

public class LdVerifiersTest extends TestCase {

	public void testLdVerifiers() throws Exception {

		assertEquals(LdVerifier.ldVerifierForSignatureSuite("Ed25519Signature2018").getClass(), Ed25519Signature2018LdVerifier.class);
		assertEquals(LdVerifier.ldVerifierForSignatureSuite("EcdsaKoblitzSignature2016").getClass(), EcdsaKoblitzSignature2016LdVerifier.class);
		assertEquals(LdVerifier.ldVerifierForSignatureSuite("RsaSignature2018").getClass(), RsaSignature2018LdVerifier.class);
	}
}
