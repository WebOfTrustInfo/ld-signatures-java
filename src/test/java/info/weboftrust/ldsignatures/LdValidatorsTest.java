package info.weboftrust.ldsignatures;

import info.weboftrust.ldsignatures.validator.EcdsaKoblitzSignature2016LdValidator;
import info.weboftrust.ldsignatures.validator.Ed25519Signature2018LdValidator;
import info.weboftrust.ldsignatures.validator.LdValidator;
import info.weboftrust.ldsignatures.validator.RsaSignature2018LdValidator;
import junit.framework.TestCase;

public class LdValidatorsTest extends TestCase {

	public void testLdValidators() throws Exception {

		assertEquals(LdValidator.ldValidatorForSignatureSuite("Ed25519Signature2018").getClass(), Ed25519Signature2018LdValidator.class);
		assertEquals(LdValidator.ldValidatorForSignatureSuite("EcdsaKoblitzSignature2016").getClass(), EcdsaKoblitzSignature2016LdValidator.class);
		assertEquals(LdValidator.ldValidatorForSignatureSuite("RsaSignature2018").getClass(), RsaSignature2018LdValidator.class);
	}
}
