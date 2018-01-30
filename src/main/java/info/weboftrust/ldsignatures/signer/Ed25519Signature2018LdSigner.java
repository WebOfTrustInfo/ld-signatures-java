package info.weboftrust.ldsignatures.signer;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;

import org.jose4j.base64url.internal.apache.commons.codec.binary.Base64;

import info.weboftrust.ldsignatures.crypto.EC25519Provider;
import info.weboftrust.ldsignatures.suites.Ed25519Signature2018SignatureSuite;
import info.weboftrust.ldsignatures.suites.SignatureSuites;

public class Ed25519Signature2018LdSigner extends LdSigner<Ed25519Signature2018SignatureSuite> {

	private byte[] privateKey;

	public Ed25519Signature2018LdSigner(URI creator, String created, String domain, String nonce, byte[] privateKey) {

		super(SignatureSuites.SIGNATURE_SUITE_ED25519SIGNATURE2018, creator, created, domain, nonce);

		this.privateKey = privateKey;
	}

	public static String sign(String canonicalizedDocument, byte[] privateKey) throws GeneralSecurityException {

		// sign

		byte[] signatureBytes = EC25519Provider.get().sign(canonicalizedDocument.getBytes(StandardCharsets.UTF_8), privateKey);
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

	public byte[] getPrivateKey() {

		return this.privateKey;
	}

	public void setPrivateKey(byte[] privateKey) {

		this.privateKey = privateKey;
	}
}
