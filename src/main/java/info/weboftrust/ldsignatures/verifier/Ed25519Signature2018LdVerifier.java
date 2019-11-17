package info.weboftrust.ldsignatures.verifier;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;

import org.apache.commons.codec.binary.Base64;

import info.weboftrust.ldsignatures.LdSignature;
import info.weboftrust.ldsignatures.crypto.EC25519Provider;
import info.weboftrust.ldsignatures.suites.Ed25519Signature2018SignatureSuite;
import info.weboftrust.ldsignatures.suites.SignatureSuites;

public class Ed25519Signature2018LdVerifier extends LdVerifier<Ed25519Signature2018SignatureSuite> {

	private Verifier verifier;

	public Ed25519Signature2018LdVerifier(Verifier verifier) {

		super(SignatureSuites.SIGNATURE_SUITE_ED25519SIGNATURE2018);

		this.verifier = verifier;
	}

	public Ed25519Signature2018LdVerifier(byte[] publicKey) {

		this(new PublicKeyVerifier(publicKey));
	}

	public Ed25519Signature2018LdVerifier() {

		this((Verifier) null);
	}

	public static boolean verify(String canonicalizedDocument, LdSignature ldSignature, Verifier verifier) throws GeneralSecurityException {

		// verify

		byte[] canonicalizedDocumentBytes = canonicalizedDocument.getBytes(StandardCharsets.UTF_8);
		byte[] signatureValueBytes = Base64.decodeBase64(ldSignature.getSignatureValue());
		boolean verify = verifier.verify(canonicalizedDocumentBytes, signatureValueBytes);

		// done

		return verify;
	}

	@Override
	public boolean verify(String canonicalizedDocument, LdSignature ldSignature) throws GeneralSecurityException {

		return verify(canonicalizedDocument, ldSignature, this.getVerifier());
	}

	/*
	 * Helper class
	 */

	public interface Verifier {

		public boolean verify(byte[] content, byte[] signature) throws GeneralSecurityException;
	}

	public static class PublicKeyVerifier implements Verifier {

		private byte[] publicKey;

		public PublicKeyVerifier(byte[] publicKey) {

			this.publicKey = publicKey;
		}

		@Override
		public boolean verify(byte[] content, byte[] signature) throws GeneralSecurityException {

			return EC25519Provider.get().verify(content, signature, this.publicKey);
		}
	}

	/*
	 * Getters and setters
	 */

	public Verifier getVerifier() {

		return this.verifier;
	}

	public void setVerifier(Verifier verifier) {

		this.verifier = verifier;
	}
}
