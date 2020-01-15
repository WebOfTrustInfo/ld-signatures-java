package info.weboftrust.ldsignatures.verifier;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;

import org.apache.commons.codec.binary.Base64;

import info.weboftrust.ldsignatures.LdSignature;
import info.weboftrust.ldsignatures.crypto.ByteVerifier;
import info.weboftrust.ldsignatures.crypto.impl.Ed25519_EdDSA_PublicKeyVerifier;
import info.weboftrust.ldsignatures.suites.Ed25519Signature2018SignatureSuite;
import info.weboftrust.ldsignatures.suites.SignatureSuites;

public class Ed25519Signature2018LdVerifier extends LdVerifier<Ed25519Signature2018SignatureSuite> {

	public Ed25519Signature2018LdVerifier(ByteVerifier verifier) {

		super(SignatureSuites.SIGNATURE_SUITE_ED25519SIGNATURE2018, verifier);
	}

	public Ed25519Signature2018LdVerifier(byte[] publicKey) {

		this(new Ed25519_EdDSA_PublicKeyVerifier(publicKey));
	}

	public Ed25519Signature2018LdVerifier() {

		this((ByteVerifier) null);
	}

	public static boolean verify(String canonicalizedDocument, LdSignature ldSignature, ByteVerifier verifier) throws GeneralSecurityException {

		// verify

		byte[] canonicalizedDocumentBytes = canonicalizedDocument.getBytes(StandardCharsets.UTF_8);
		byte[] signatureValueBytes = Base64.decodeBase64(ldSignature.getSignatureValue());
		boolean verify = verifier.verify(canonicalizedDocumentBytes, signatureValueBytes, "EdDSA");

		// done

		return verify;
	}

	@Override
	public boolean verify(String canonicalizedDocument, LdSignature ldSignature) throws GeneralSecurityException {

		return verify(canonicalizedDocument, ldSignature, this.getVerifier());
	}
}
