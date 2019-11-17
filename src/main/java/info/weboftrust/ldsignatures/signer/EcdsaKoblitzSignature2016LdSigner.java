package info.weboftrust.ldsignatures.signer;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;

import org.apache.commons.codec.binary.Base64;
import org.bitcoinj.core.ECKey;
import org.bitcoinj.core.Sha256Hash;

import info.weboftrust.ldsignatures.suites.EcdsaKoblitzSignature2016SignatureSuite;
import info.weboftrust.ldsignatures.suites.SignatureSuites;

public class EcdsaKoblitzSignature2016LdSigner extends LdSigner<EcdsaKoblitzSignature2016SignatureSuite> {

	private Signer signer;

	public EcdsaKoblitzSignature2016LdSigner(Signer signer) {

		super(SignatureSuites.SIGNATURE_SUITE_ECDSAKOBLITZSIGNATURE2016);

		this.signer = signer;
	}

	public EcdsaKoblitzSignature2016LdSigner(ECKey privateKey) {

		this(new PrivateKeySigner(privateKey));
	}

	public EcdsaKoblitzSignature2016LdSigner() {

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

		private ECKey privateKey;

		public PrivateKeySigner(ECKey privateKey) {

			this.privateKey = privateKey;
		}

		public byte[] sign(byte[] content) throws GeneralSecurityException {

			return this.privateKey.sign(Sha256Hash.of(content)).encodeToDER();
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
