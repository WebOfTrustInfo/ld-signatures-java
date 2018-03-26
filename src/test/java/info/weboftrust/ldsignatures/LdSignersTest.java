package info.weboftrust.ldsignatures;

import info.weboftrust.ldsignatures.signer.EcdsaKoblitzSignature2016LdSigner;
import info.weboftrust.ldsignatures.signer.Ed25519Signature2018LdSigner;
import info.weboftrust.ldsignatures.signer.LdSigner;
import info.weboftrust.ldsignatures.signer.RsaSignature2017LdSigner;
import junit.framework.TestCase;

public class LdSignersTest extends TestCase {

	public void testLdSigners() throws Exception {

		assertEquals(LdSigner.ldSignerForSignatureSuite("Ed25519Signature2018").getClass(), Ed25519Signature2018LdSigner.class);
		assertEquals(LdSigner.ldSignerForSignatureSuite("EcdsaKoblitzSignature2016").getClass(), EcdsaKoblitzSignature2016LdSigner.class);
		assertEquals(LdSigner.ldSignerForSignatureSuite("RsaSignature2017").getClass(), RsaSignature2017LdSigner.class);
	}
}
