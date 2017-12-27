package info.weboftrust.ldsignatures.validator;

import java.security.interfaces.RSAPublicKey;

import info.weboftrust.ldsignatures.suites.RsaSignature2017SignatureSuite;
import info.weboftrust.ldsignatures.suites.SignatureSuites;

public class RsaSignature2017LdValidator extends LdValidator<RsaSignature2017SignatureSuite> {

	private RSAPublicKey publicKey;

	public RsaSignature2017LdValidator(RSAPublicKey publicKey) {

		super(SignatureSuites.SIGNATURE_SUITE_RSASIGNATURE2017);

		this.publicKey = publicKey;
	}
}
