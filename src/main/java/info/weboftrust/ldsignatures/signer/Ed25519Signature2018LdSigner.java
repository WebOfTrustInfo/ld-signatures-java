package info.weboftrust.ldsignatures.signer;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.concurrent.ExecutionException;

import org.apache.commons.codec.binary.Base64;
import org.hyperledger.indy.sdk.IndyException;
import org.hyperledger.indy.sdk.crypto.Crypto;
import org.hyperledger.indy.sdk.wallet.Wallet;

import info.weboftrust.ldsignatures.crypto.EC25519Provider;
import info.weboftrust.ldsignatures.suites.Ed25519Signature2018SignatureSuite;
import info.weboftrust.ldsignatures.suites.SignatureSuites;

public class Ed25519Signature2018LdSigner extends LdSigner<Ed25519Signature2018SignatureSuite> {

	private Signer signer;

	public Ed25519Signature2018LdSigner(Signer signer) {

		super(SignatureSuites.SIGNATURE_SUITE_ED25519SIGNATURE2018);

		this.signer = signer;
	}

	public Ed25519Signature2018LdSigner(byte[] privateKey) {

		this(new PrivateKeySigner(privateKey));
	}

	public Ed25519Signature2018LdSigner() {

		this((Signer) null);
	}

	public static String sign(String canonicalizedDocument, Signer signer) throws GeneralSecurityException {

		// sign

		byte[] canonicalizedDocumentBytes = canonicalizedDocument.getBytes(StandardCharsets.UTF_8);
		byte[] signatureBytes = signer.sign(canonicalizedDocumentBytes);
		String signatureString = Base64.encodeBase64String(signatureBytes);

		// done

		return signatureString;
	}

	@Override
	public String sign(String canonicalizedDocument) throws GeneralSecurityException {

		return sign(canonicalizedDocument, this.getSigner());
	}

	/*
	 * Helper class
	 */

	public interface Signer {

		public byte[] sign(byte[] content) throws GeneralSecurityException;
	}

	public static class PrivateKeySigner implements Signer {

		private byte[] privateKey;

		public PrivateKeySigner(byte[] privateKey) {

			this.privateKey = privateKey;
		}

		@Override
		public byte[] sign(byte[] content) throws GeneralSecurityException {

			return EC25519Provider.get().sign(content, this.privateKey);
		}
	}

	public static class LibIndySigner implements Signer {

		private Wallet wallet;
		private String signerVk;

		public LibIndySigner(Wallet wallet, String signerVk) {

			this.wallet = wallet;
			this.signerVk = signerVk;
		}

		@Override
		public byte[] sign(byte[] content) throws GeneralSecurityException {

			try {

				return Crypto.cryptoSign(this.wallet, this.signerVk, content).get();
			} catch (InterruptedException | ExecutionException | IndyException ex) {

				throw new GeneralSecurityException(ex.getMessage(), ex);
			}
		}
	}

	/*
	 * Getters and setters
	 */

	public Signer getSigner() {

		return this.signer;
	}

	public void setSigner(Signer signer) {

		this.signer = signer;
	}
}
