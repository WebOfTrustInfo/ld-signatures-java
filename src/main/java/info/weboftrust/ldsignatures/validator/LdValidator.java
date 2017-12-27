package info.weboftrust.ldsignatures.validator;

import info.weboftrust.ldsignatures.suites.SignatureSuite;

public abstract class LdValidator <SIGNATURESUITE extends SignatureSuite> {

	protected SIGNATURESUITE signatureSuite;

	protected LdValidator(SIGNATURESUITE signatureSuite) {

		this.signatureSuite = signatureSuite;
	}
}
