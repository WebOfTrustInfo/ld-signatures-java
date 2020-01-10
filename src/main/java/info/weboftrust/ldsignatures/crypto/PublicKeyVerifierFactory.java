package info.weboftrust.ldsignatures.crypto;

import java.security.interfaces.RSAPublicKey;

import org.bitcoinj.core.ECKey;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.KeyType;

import info.weboftrust.ldsignatures.crypto.impl.Ed25519_EdDSA_PublicKeyVerifier;
import info.weboftrust.ldsignatures.crypto.impl.P256K_ES256K_PublicKeyVerifier;
import info.weboftrust.ldsignatures.crypto.impl.RSA_PS256_PublicKeyVerifier;
import info.weboftrust.ldsignatures.crypto.impl.RSA_RS256_PublicKeyVerifier;

public class PublicKeyVerifierFactory {

	public static PublicKeyVerifier<?> publicKeyVerifierForKey(String keyType, String algorithm, Object publicKey) throws JOSEException {

		if (keyType == null) throw new NullPointerException("No key type provided.");
		if (algorithm == null) throw new NullPointerException("No algorithm provided.");
		if (publicKey == null) throw new NullPointerException("No public key provided.");

		if (KeyType.RSA.getValue().equals(keyType)) {

			if (JWSAlgorithm.RS256.getName().equals(algorithm)) return new RSA_RS256_PublicKeyVerifier((RSAPublicKey) publicKey);
			if (JWSAlgorithm.PS256.getName().equals(algorithm)) return new RSA_PS256_PublicKeyVerifier((RSAPublicKey) publicKey);
		} else if (Curve.P_256K.getName().equals(keyType)) {

			if (JWSAlgorithm.ES256K.getName().equals(algorithm)) return new P256K_ES256K_PublicKeyVerifier((ECKey) publicKey);
		} else if (Curve.Ed25519.getName().equals(keyType)) {

			if (JWSAlgorithm.EdDSA.getName().equals(algorithm)) return new Ed25519_EdDSA_PublicKeyVerifier((byte[]) publicKey);
		}

		throw new IllegalArgumentException("Unsupported key " + keyType + " and/or algorithm " + algorithm);
	}
}
