package info.weboftrust.ldsignatures;

import info.weboftrust.ldsignatures.suites.SignatureSuite;
import info.weboftrust.ldsignatures.suites.SignatureSuites;
import info.weboftrust.ldsignatures.verifier.LdVerifierRegistry;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class LdVerifierRegistryTest {

	@Test
	public void testLdVerifierRegistry() throws Exception {

		for (SignatureSuite signatureSuite : SignatureSuites.SIGNATURE_SUITES) {
			assertEquals(LdVerifierRegistry.getLdVerifierBySignatureSuite(signatureSuite).getSignatureSuite(), signatureSuite);
		}

		for (SignatureSuite signatureSuite : SignatureSuites.SIGNATURE_SUITES) {
			assertEquals(LdVerifierRegistry.getLdVerifierBySignatureSuiteTerm(signatureSuite.getTerm()).getSignatureSuite(), signatureSuite);
		}

		for (SignatureSuite signatureSuite : SignatureSuites.SIGNATURE_SUITES) {
			assertEquals(LdVerifierRegistry.getLdVerifierBySignatureSuite(signatureSuite).getClass(), LdVerifierRegistry.getLdVerifierBySignatureSuiteTerm(signatureSuite.getTerm()).getClass());
		}
	}
}
