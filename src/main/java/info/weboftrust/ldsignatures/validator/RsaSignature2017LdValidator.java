package info.weboftrust.ldsignatures.validator;

import java.security.interfaces.RSAPublicKey;

import info.weboftrust.ldsignatures.suites.RsaSignature2017SignatureSuite;

public class RsaSignature2017LdValidator extends LdValidator<RsaSignature2017SignatureSuite> {

	private Object jsonLdObject;
	private RSAPublicKey publicKey;

	public RsaSignature2017LdValidator(Object jsonLdObject, RSAPublicKey publicKey) {

		super();

		this.jsonLdObject = jsonLdObject;
		this.publicKey = publicKey;
	}
}
