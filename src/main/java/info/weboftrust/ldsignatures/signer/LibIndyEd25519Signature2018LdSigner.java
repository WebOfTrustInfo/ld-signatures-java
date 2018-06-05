package info.weboftrust.ldsignatures.signer;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.concurrent.ExecutionException;

import org.hyperledger.indy.sdk.IndyException;
import org.hyperledger.indy.sdk.crypto.Crypto;
import org.hyperledger.indy.sdk.wallet.Wallet;
import org.jose4j.base64url.internal.apache.commons.codec.binary.Base64;

import info.weboftrust.ldsignatures.suites.Ed25519Signature2018SignatureSuite;
import info.weboftrust.ldsignatures.suites.SignatureSuites;

public class LibIndyEd25519Signature2018LdSigner extends LdSigner<Ed25519Signature2018SignatureSuite> {

	private Wallet wallet;
	private String signerVk;

	public LibIndyEd25519Signature2018LdSigner() {

		super(SignatureSuites.SIGNATURE_SUITE_ED25519SIGNATURE2018);
	}

	public LibIndyEd25519Signature2018LdSigner(URI creator, String created, String domain, String nonce, Wallet wallet, String signerVk) {

		super(SignatureSuites.SIGNATURE_SUITE_ED25519SIGNATURE2018, creator, created, domain, nonce);

		this.wallet = wallet;
		this.signerVk = signerVk;
	}

	public static String sign(String canonicalizedDocument, Wallet wallet, String signerVk) throws GeneralSecurityException {

		// sign

		byte[] canonicalizedDocumentBytes = canonicalizedDocument.getBytes(StandardCharsets.UTF_8);
		byte[] signatureBytes;

		try {

			signatureBytes = Crypto.cryptoSign(wallet, signerVk, canonicalizedDocumentBytes).get();
		} catch (InterruptedException | ExecutionException | IndyException ex) {

			throw new GeneralSecurityException(ex.getMessage(), ex);
		}

		String signatureString = Base64.encodeBase64String(signatureBytes);

		// done

		return signatureString;
	}

	@Override
	public String sign(String canonicalizedDocument) throws GeneralSecurityException {

		return sign(canonicalizedDocument, this.getWallet(), this.getSignerVk());
	}

	/*
	 * Getters and setters
	 */

	public Wallet getWallet() {

		return this.wallet;
	}

	public void setWallet(Wallet wallet) {

		this.wallet = wallet;
	}

	public String getSignerVk() {

		return this.signerVk;
	}

	public void setSignerVk(String signerVk) {

		this.signerVk = signerVk;
	}
}
