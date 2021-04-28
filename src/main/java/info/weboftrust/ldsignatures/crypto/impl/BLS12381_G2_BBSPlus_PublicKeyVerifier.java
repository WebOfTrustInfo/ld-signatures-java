package info.weboftrust.ldsignatures.crypto.impl;

import bbs.signatures.Bbs;
import info.weboftrust.ldsignatures.crypto.PublicKeyVerifier;
import info.weboftrust.ldsignatures.crypto.jose.JWSAlgorithms;
import org.bitcoinj.core.ECKey;
import org.bitcoinj.core.Sha256Hash;
import org.bitcoinj.core.SignatureDecodeException;

import java.security.GeneralSecurityException;

public class BLS12381_G2_BBSPlus_PublicKeyVerifier extends PublicKeyVerifier<ECKey> {

	public BLS12381_G2_BBSPlus_PublicKeyVerifier(ECKey publicKey) {

		super(publicKey, JWSAlgorithms.BBSPlus.getName());
	}

	@Override
	public boolean verify(byte[] content, byte[] signature) throws GeneralSecurityException {

		try {

			return Bbs.verify(this.getPublicKey().getPubKey(), signature, new byte[][] { signature });
		} catch (GeneralSecurityException ex) {

			throw ex;
		} catch (Exception ex) {

			throw new GeneralSecurityException(ex.getMessage(), ex);
		}
	}
}
