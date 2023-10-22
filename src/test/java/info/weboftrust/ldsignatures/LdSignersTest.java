package info.weboftrust.ldsignatures;

import info.weboftrust.ldsignatures.signer.*;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class LdSignersTest {

	@Test
	public void testLdSigners() throws Exception {

		assertEquals(LdSignerRegistry.getLdSignerBySignatureSuiteTerm("RsaSignature2018").getClass(), RsaSignature2018LdSigner.class);
		assertEquals(LdSignerRegistry.getLdSignerBySignatureSuiteTerm("Ed25519Signature2018").getClass(), Ed25519Signature2018LdSigner.class);
		assertEquals(LdSignerRegistry.getLdSignerBySignatureSuiteTerm("Ed25519Signature2020").getClass(), Ed25519Signature2020LdSigner.class);
		assertEquals(LdSignerRegistry.getLdSignerBySignatureSuiteTerm("JcsEd25519Signature2020").getClass(), JcsEd25519Signature2020LdSigner.class);
		assertEquals(LdSignerRegistry.getLdSignerBySignatureSuiteTerm("EcdsaKoblitzSignature2016").getClass(), EcdsaKoblitzSignature2016LdSigner.class);
		assertEquals(LdSignerRegistry.getLdSignerBySignatureSuiteTerm("EcdsaSecp256k1Signature2019").getClass(), EcdsaSecp256k1Signature2019LdSigner.class);
		assertEquals(LdSignerRegistry.getLdSignerBySignatureSuiteTerm("JcsEcdsaSecp256k1Signature2019").getClass(), JcsEcdsaSecp256k1Signature2019LdSigner.class);
		assertEquals(LdSignerRegistry.getLdSignerBySignatureSuiteTerm("BbsBlsSignature2020").getClass(), BbsBlsSignature2020LdSigner.class);
		assertEquals(LdSignerRegistry.getLdSignerBySignatureSuiteTerm("JsonWebSignature2020").getClass(), JsonWebSignature2020LdSigner.class);
	}
}
