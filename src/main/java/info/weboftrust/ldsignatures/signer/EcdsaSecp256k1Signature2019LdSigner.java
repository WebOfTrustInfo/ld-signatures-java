package info.weboftrust.ldsignatures.signer;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;

import org.bitcoinj.core.ECKey;
import org.bitcoinj.core.Sha256Hash;
import org.jose4j.base64url.internal.apache.commons.codec.binary.Base64;

import info.weboftrust.ldsignatures.suites.EcdsaSecp256k1Signature2019SignatureSuite;
import info.weboftrust.ldsignatures.suites.SignatureSuites;

public class EcdsaSecp256k1Signature2019LdSigner extends LdSigner<EcdsaSecp256k1Signature2019SignatureSuite> {

	private ECKey privateKey;

	public EcdsaSecp256k1Signature2019LdSigner() {

		super(SignatureSuites.SIGNATURE_SUITE_ECDSASECP256L1SIGNATURE2019);
	}

	public EcdsaSecp256k1Signature2019LdSigner(URI creator, String created, String domain, String nonce, ECKey privateKey) {

		super(SignatureSuites.SIGNATURE_SUITE_ECDSASECP256L1SIGNATURE2019, creator, created, domain, nonce);

		this.privateKey = privateKey;
	}

	public static String sign(String canonicalizedDocument, ECKey privateKey) throws GeneralSecurityException {

		// sign

		byte[] canonicalizedDocumentBytes = canonicalizedDocument.getBytes(StandardCharsets.UTF_8);
		byte[] signatureBytes = privateKey.sign(Sha256Hash.of(canonicalizedDocumentBytes)).encodeToDER();
		String signatureString = Base64.encodeBase64String(signatureBytes);

		// done

		return signatureString;
	}

	@Override
	public String sign(String canonicalizedDocument) throws GeneralSecurityException {

		return sign(canonicalizedDocument, this.privateKey);
	}

	/*
	 * Getters and setters
	 */

	public ECKey getPrivateKey() {

		return this.privateKey;
	}

	public void setPrivateKey(ECKey privateKey) {

		this.privateKey = privateKey;
	}
}
