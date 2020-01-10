package info.weboftrust.ldsignatures.signer;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;

import org.apache.commons.codec.binary.Base64;

import info.weboftrust.ldsignatures.crypto.ByteSigner;
import info.weboftrust.ldsignatures.crypto.impl.Ed25519_EdDSA_PrivateKeySigner;
import info.weboftrust.ldsignatures.suites.Ed25519Signature2018SignatureSuite;
import info.weboftrust.ldsignatures.suites.SignatureSuites;

public class Ed25519Signature2018LdSigner extends LdSigner<Ed25519Signature2018SignatureSuite> {

	private ByteSigner signer;

	public Ed25519Signature2018LdSigner(ByteSigner signer) {

		super(SignatureSuites.SIGNATURE_SUITE_ED25519SIGNATURE2018);

		this.signer = signer;
	}

	public Ed25519Signature2018LdSigner(byte[] privateKey) {

		this(new Ed25519_EdDSA_PrivateKeySigner(privateKey));
	}

	public Ed25519Signature2018LdSigner() {

		this((ByteSigner) null);
	}

	public static String sign(String canonicalizedDocument, ByteSigner signer) throws GeneralSecurityException {

		// sign

		byte[] canonicalizedDocumentBytes = canonicalizedDocument.getBytes(StandardCharsets.UTF_8);
		byte[] signatureBytes = signer.sign(canonicalizedDocumentBytes, "EdDSA");
		String signatureString = Base64.encodeBase64String(signatureBytes);

		// done

		return signatureString;
	}

	@Override
	public String sign(String canonicalizedDocument) throws GeneralSecurityException {

		return sign(canonicalizedDocument, this.getSigner());
	}

	/*
	 * Getters and setters
	 */

	public ByteSigner getSigner() {

		return this.signer;
	}

	public void setSigner(ByteSigner signer) {

		this.signer = signer;
	}
}
