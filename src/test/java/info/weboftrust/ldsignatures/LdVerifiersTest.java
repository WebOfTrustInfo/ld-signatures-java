package info.weboftrust.ldsignatures;

import info.weboftrust.ldsignatures.verifier.*;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class LdVerifiersTest {

	@Test
	public void testLdVerifiers() throws Exception {

		assertEquals(LdVerifier.ldVerifierForSignatureSuite("RsaSignature2018").getClass(), RsaSignature2018LdVerifier.class);
		assertEquals(LdVerifier.ldVerifierForSignatureSuite("Ed25519Signature2018").getClass(), Ed25519Signature2018LdVerifier.class);
		assertEquals(LdVerifier.ldVerifierForSignatureSuite("Ed25519Signature2020").getClass(), Ed25519Signature2020LdVerifier.class);
		assertEquals(LdVerifier.ldVerifierForSignatureSuite("EcdsaKoblitzSignature2016").getClass(), EcdsaKoblitzSignature2016LdVerifier.class);
		assertEquals(LdVerifier.ldVerifierForSignatureSuite("EcdsaSecp256k1Signature2019").getClass(), EcdsaSecp256k1Signature2019LdVerifier.class);
		assertEquals(LdVerifier.ldVerifierForSignatureSuite("BbsBlsSignature2020").getClass(), BBSPlusSignature2020LdVerifier.class);
		assertEquals(LdVerifier.ldVerifierForSignatureSuite("JsonWebSignature2020").getClass(), JsonWebSignature2020Verifier.class);
	}
}
