package info.weboftrust.ldsignatures.verifier;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;

import org.apache.commons.codec.binary.Base64;
import org.bitcoinj.core.ECKey;

import info.weboftrust.ldsignatures.LdSignature;
import info.weboftrust.ldsignatures.crypto.ByteVerifier;
import info.weboftrust.ldsignatures.crypto.impl.P256K_ES256K_PublicKeyVerifier;
import info.weboftrust.ldsignatures.suites.EcdsaSecp256k1Signature2019SignatureSuite;
import info.weboftrust.ldsignatures.suites.SignatureSuites;

public class EcdsaSecp256k1Signature2019LdVerifier extends LdVerifier<EcdsaSecp256k1Signature2019SignatureSuite> {

	public EcdsaSecp256k1Signature2019LdVerifier(ByteVerifier verifier) {

		super(SignatureSuites.SIGNATURE_SUITE_ECDSASECP256L1SIGNATURE2019, verifier);
	}

	public EcdsaSecp256k1Signature2019LdVerifier(ECKey publicKey) {

		this(new P256K_ES256K_PublicKeyVerifier(publicKey));
	}

	public EcdsaSecp256k1Signature2019LdVerifier() {

		this((ByteVerifier) null);
	}

	public static boolean verify(String canonicalizedDocument, LdSignature ldSignature, ByteVerifier verifier) throws GeneralSecurityException {

		// verify

		byte[] canonicalizedDocumentBytes = canonicalizedDocument.getBytes(StandardCharsets.UTF_8);
		byte[] signatureValueBytes = Base64.decodeBase64(ldSignature.getSignatureValue());
		boolean verify = verifier.verify(canonicalizedDocumentBytes, signatureValueBytes, "ES256K");

		// done

		return verify;
	}

	@Override
	public boolean verify(String canonicalizedDocument, LdSignature ldSignature) throws GeneralSecurityException {

		return verify(canonicalizedDocument, ldSignature, this.getVerifier());
	}
}
