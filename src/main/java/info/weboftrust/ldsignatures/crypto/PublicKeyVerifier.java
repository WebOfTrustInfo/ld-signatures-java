package info.weboftrust.ldsignatures.crypto;

public abstract class PublicKeyVerifier <T> extends ByteVerifier {

	private T publicKey;

	protected PublicKeyVerifier(T publicKey, String algorithm) {

		super(algorithm);

		this.publicKey = publicKey;
	}

	protected T getPublicKey() {

		return this.publicKey;
	}
}
