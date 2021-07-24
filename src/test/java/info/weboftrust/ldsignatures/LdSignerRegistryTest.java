package info.weboftrust.ldsignatures;

import info.weboftrust.ldsignatures.signer.LdSignerRegistry;
import info.weboftrust.ldsignatures.suites.SignatureSuite;
import info.weboftrust.ldsignatures.suites.SignatureSuites;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class LdSignerRegistryTest {

	@Test
	public void testLdSignerRegistry() throws Exception {

		for (SignatureSuite signatureSuite : SignatureSuites.SIGNATURE_SUITES) {
			assertEquals(LdSignerRegistry.getLdSignerBySignatureSuite(signatureSuite).getSignatureSuite(), signatureSuite);
		}

		for (SignatureSuite signatureSuite : SignatureSuites.SIGNATURE_SUITES) {
			assertEquals(LdSignerRegistry.getLdSignerBySignatureSuiteTerm(signatureSuite.getTerm()).getSignatureSuite(), signatureSuite);
		}

		for (SignatureSuite signatureSuite : SignatureSuites.SIGNATURE_SUITES) {
			assertEquals(LdSignerRegistry.getLdSignerBySignatureSuite(signatureSuite).getClass(), LdSignerRegistry.getLdSignerBySignatureSuiteTerm(signatureSuite.getTerm()).getClass());
		}
	}
}
