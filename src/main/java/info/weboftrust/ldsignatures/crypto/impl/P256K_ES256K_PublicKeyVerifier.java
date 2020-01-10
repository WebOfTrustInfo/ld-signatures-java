package info.weboftrust.ldsignatures.crypto.impl;

import java.security.GeneralSecurityException;

import org.bitcoinj.core.ECKey;
import org.bitcoinj.core.Sha256Hash;
import org.bitcoinj.core.SignatureDecodeException;

import info.weboftrust.ldsignatures.crypto.PublicKeyVerifier;

public class P256K_ES256K_PublicKeyVerifier extends PublicKeyVerifier<ECKey> {

	public P256K_ES256K_PublicKeyVerifier(ECKey publicKey) {

		super(publicKey, "ES256K");
	}

	@Override
	public boolean verify(byte[] content, byte[] signature) throws GeneralSecurityException {

		try {

			return this.getPublicKey().verify(Sha256Hash.hash(content), signature);
		} catch (SignatureDecodeException ex) {
			
			throw new GeneralSecurityException(ex.getMessage(), ex);
		}
	}
}
