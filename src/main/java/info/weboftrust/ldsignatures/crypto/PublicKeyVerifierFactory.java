package info.weboftrust.ldsignatures.crypto;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.KeyType;
import info.weboftrust.ldsignatures.crypto.impl.*;
import info.weboftrust.ldsignatures.crypto.jose.Curves;
import info.weboftrust.ldsignatures.crypto.jose.JWSAlgorithms;
import org.bitcoinj.core.ECKey;

import java.security.interfaces.RSAPublicKey;

public class PublicKeyVerifierFactory {

    public static PublicKeyVerifier<?> publicKeyVerifierForKey(String keyType, String algorithm, Object publicKey) throws JOSEException {

        if (keyType == null) throw new NullPointerException("No key type provided.");
        if (algorithm == null) throw new NullPointerException("No algorithm provided.");
        if (publicKey == null) throw new NullPointerException("No public key provided.");

        if (KeyType.RSA.getValue().equals(keyType)) {

            if (JWSAlgorithm.RS256.getName().equals(algorithm))
                return new RSA_RS256_PublicKeyVerifier((RSAPublicKey) publicKey);
            if (JWSAlgorithm.PS256.getName().equals(algorithm))
                return new RSA_PS256_PublicKeyVerifier((RSAPublicKey) publicKey);
        } else if (Curve.SECP256K1.getName().equals(keyType)) {

            if (JWSAlgorithm.ES256K.getName().equals(algorithm))
                return new secp256k1_ES256K_PublicKeyVerifier((ECKey) publicKey);
        } else if (Curves.BLS12381_G1.getName().equals(keyType)) {

            if (JWSAlgorithms.BBSPlus.getName().equals(algorithm))
                return new BLS12381_G1_BBSPlus_PublicKeyVerifier((ECKey) publicKey);
        } else if (Curves.BLS12381_G2.getName().equals(keyType)) {

            if (JWSAlgorithms.BBSPlus.getName().equals(algorithm))
                return new BLS12381_G2_BBSPlus_PublicKeyVerifier((ECKey) publicKey);
        } else if (Curve.Ed25519.getName().equals(keyType)) {

            if (JWSAlgorithm.EdDSA.getName().equals(algorithm))
                return new Ed25519_EdDSA_PublicKeyVerifier((byte[]) publicKey);
        }

        throw new IllegalArgumentException("Unsupported key " + keyType + " and/or algorithm " + algorithm);
    }
}
