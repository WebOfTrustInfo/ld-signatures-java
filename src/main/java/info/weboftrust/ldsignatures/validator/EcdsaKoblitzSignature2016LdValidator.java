package info.weboftrust.ldsignatures.validator;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;

import org.apache.commons.codec.binary.Base64;
import org.bitcoinj.core.ECKey;
import org.bitcoinj.core.Sha256Hash;

import info.weboftrust.ldsignatures.LdSignature;
import info.weboftrust.ldsignatures.suites.EcdsaKoblitzSignature2016SignatureSuite;
import info.weboftrust.ldsignatures.suites.SignatureSuites;

public class EcdsaKoblitzSignature2016LdValidator extends LdValidator<EcdsaKoblitzSignature2016SignatureSuite> {

	private ECKey publicKey;

	public EcdsaKoblitzSignature2016LdValidator(ECKey publicKey) {

		super(SignatureSuites.SIGNATURE_SUITE_ECDSAKOBLITZSIGNATURE2016);

		this.publicKey = publicKey;
	}

	public static boolean validate(String canonicalizedDocument, LdSignature ldSignature, ECKey publicKey) throws GeneralSecurityException {

		// validate

		byte[] canonicalizedDocumentBytes = canonicalizedDocument.getBytes(StandardCharsets.UTF_8);
		byte[] signatureValueBytes = Base64.decodeBase64(ldSignature.getSignatureValue());
		boolean validate = publicKey.verify(Sha256Hash.hash(canonicalizedDocumentBytes), signatureValueBytes);

		// done

		return validate;
	}

	@Override
	public boolean validate(String canonicalizedDocument, LdSignature ldSignature) throws GeneralSecurityException {

		return validate(canonicalizedDocument, ldSignature, this.publicKey);
	}

	/*
	 * Getters and setters
	 */

	public ECKey getPublicKey() {

		return this.publicKey;
	}

	public void setPublicKey(ECKey publicKey) {

		this.publicKey = publicKey;
	}
}
