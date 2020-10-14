package info.weboftrust.ldsignatures;

import info.weboftrust.ldsignatures.signer.EcdsaKoblitzSignature2016LdSigner;
import info.weboftrust.ldsignatures.signer.Ed25519Signature2018LdSigner;
import info.weboftrust.ldsignatures.signer.LdSigner;
import info.weboftrust.ldsignatures.signer.RsaSignature2018LdSigner;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class LdSignersTest {

	@Test
	public void testLdSigners() throws Exception {

		assertEquals(LdSigner.ldSignerForSignatureSuite("Ed25519Signature2018").getClass(), Ed25519Signature2018LdSigner.class);
		assertEquals(LdSigner.ldSignerForSignatureSuite("EcdsaKoblitzSignature2016").getClass(), EcdsaKoblitzSignature2016LdSigner.class);
		assertEquals(LdSigner.ldSignerForSignatureSuite("RsaSignature2018").getClass(), RsaSignature2018LdSigner.class);
	}
}
