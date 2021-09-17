package info.weboftrust.ldsignatures;

import com.danubetech.keyformats.jose.KeyTypeName;
import info.weboftrust.ldsignatures.suites.SignatureSuites;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class SignatureSuitesTest {

	@Test
	public void testSignatureSuites() throws Exception {

		assertEquals(SignatureSuites.findSignatureSuitesByKeyTypeName(KeyTypeName.RSA).size(), 2);
		assertEquals(SignatureSuites.findSignatureSuitesByKeyTypeName(KeyTypeName.secp256k1).size(), 4);
		assertEquals(SignatureSuites.findSignatureSuitesByKeyTypeName(KeyTypeName.Ed25519).size(), 4);
		assertEquals(SignatureSuites.findSignatureSuitesByKeyTypeName(KeyTypeName.P_256).size(), 1);
		assertEquals(SignatureSuites.findSignatureSuitesByKeyTypeName(KeyTypeName.P_384).size(), 1);
		assertEquals(SignatureSuites.findSignatureSuitesByKeyTypeName(KeyTypeName.Bls12381G1).size(), 1);
		assertEquals(SignatureSuites.findSignatureSuitesByKeyTypeName(KeyTypeName.Bls12381G2).size(), 1);

		assertTrue(SignatureSuites.findSignatureSuitesByKeyTypeName(KeyTypeName.RSA).contains(SignatureSuites.SIGNATURE_SUITE_RSASIGNATURE2018));
		assertTrue(SignatureSuites.findSignatureSuitesByKeyTypeName(KeyTypeName.secp256k1).contains(SignatureSuites.SIGNATURE_SUITE_ECDSAKOBLITZSIGNATURE2016));
		assertTrue(SignatureSuites.findSignatureSuitesByKeyTypeName(KeyTypeName.secp256k1).contains(SignatureSuites.SIGNATURE_SUITE_ECDSASECP256L1SIGNATURE2019));
		assertTrue(SignatureSuites.findSignatureSuitesByKeyTypeName(KeyTypeName.secp256k1).contains(SignatureSuites.SIGNATURE_SUITE_JCSECDSASECP256L1SIGNATURE2019));
		assertTrue(SignatureSuites.findSignatureSuitesByKeyTypeName(KeyTypeName.secp256k1).contains(SignatureSuites.SIGNATURE_SUITE_JSONWEBSIGNATURE2020));
		assertTrue(SignatureSuites.findSignatureSuitesByKeyTypeName(KeyTypeName.Ed25519).contains(SignatureSuites.SIGNATURE_SUITE_ED25519SIGNATURE2018));
		assertTrue(SignatureSuites.findSignatureSuitesByKeyTypeName(KeyTypeName.Ed25519).contains(SignatureSuites.SIGNATURE_SUITE_ED25519SIGNATURE2020));
		assertTrue(SignatureSuites.findSignatureSuitesByKeyTypeName(KeyTypeName.Ed25519).contains(SignatureSuites.SIGNATURE_SUITE_JCSED25519SIGNATURE2020));
		assertTrue(SignatureSuites.findSignatureSuitesByKeyTypeName(KeyTypeName.Ed25519).contains(SignatureSuites.SIGNATURE_SUITE_JSONWEBSIGNATURE2020));
		assertTrue(SignatureSuites.findSignatureSuitesByKeyTypeName(KeyTypeName.P_256).contains(SignatureSuites.SIGNATURE_SUITE_JSONWEBSIGNATURE2020));
		assertTrue(SignatureSuites.findSignatureSuitesByKeyTypeName(KeyTypeName.P_384).contains(SignatureSuites.SIGNATURE_SUITE_JSONWEBSIGNATURE2020));
		assertTrue(SignatureSuites.findSignatureSuitesByKeyTypeName(KeyTypeName.Bls12381G1).contains(SignatureSuites.SIGNATURE_SUITE_BBSBLSSIGNATURE2020));
		assertTrue(SignatureSuites.findSignatureSuitesByKeyTypeName(KeyTypeName.Bls12381G2).contains(SignatureSuites.SIGNATURE_SUITE_BBSBLSSIGNATURE2020));
	}
}
