package info.weboftrust.ldsignatures.verifier;

import com.danubetech.keyformats.crypto.ByteVerifier;
import com.danubetech.keyformats.crypto.impl.secp256k1_ES256K_PublicKeyVerifier;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.JWSVerifier;
import info.weboftrust.ldsignatures.LdProof;
import info.weboftrust.ldsignatures.adapter.JWSVerifierAdapter;
import info.weboftrust.ldsignatures.canonicalizer.RdfCanonicalizer;
import info.weboftrust.ldsignatures.suites.EcdsaSecp256k1Signature2019SignatureSuite;
import info.weboftrust.ldsignatures.suites.SignatureSuites;
import info.weboftrust.ldsignatures.util.JWSUtil;
import org.bitcoinj.core.ECKey;

import java.security.GeneralSecurityException;
import java.text.ParseException;

public class EcdsaSecp256k1Signature2019LdVerifier extends LdVerifier<EcdsaSecp256k1Signature2019SignatureSuite> {

    public EcdsaSecp256k1Signature2019LdVerifier(ByteVerifier verifier) {

        super(SignatureSuites.SIGNATURE_SUITE_ECDSASECP256L1SIGNATURE2019, verifier, new RdfCanonicalizer());
    }

    public EcdsaSecp256k1Signature2019LdVerifier(ECKey publicKey) {

        this(new secp256k1_ES256K_PublicKeyVerifier(publicKey));
    }

    public EcdsaSecp256k1Signature2019LdVerifier() {

        this((ByteVerifier) null);
    }

    public static boolean verify(byte[] signingInput, LdProof ldProof, ByteVerifier verifier) throws GeneralSecurityException {

        // build the JWS and verify

        String jws = ldProof.getJws();
        boolean verify;

        try {

            JWSObject detachedJwsObject = JWSObject.parse(jws);
            byte[] jwsSigningInput = JWSUtil.getJwsSigningInput(detachedJwsObject.getHeader(), signingInput);

            JWSVerifier jwsVerifier = new JWSVerifierAdapter(verifier, JWSAlgorithm.ES256K);
            verify = jwsVerifier.verify(detachedJwsObject.getHeader(), jwsSigningInput, detachedJwsObject.getSignature());

			/*			JsonWebSignature jws = new JsonWebSignature();
			jws.setAlgorithmConstraints(new AlgorithmConstraints(AlgorithmConstraints.ConstraintType.WHITELIST, AlgorithmIdentifiers.RSA_USING_SHA256));
			jws.setCompactSerialization(ldProof.getJws());
			jws.setPayload(unencodedPayload);

			jws.setKey(publicKey);
			verify = jws.verifySignature();*/
        } catch (JOSEException | ParseException ex) {

            throw new GeneralSecurityException("JOSE verification problem: " + ex.getMessage(), ex);
        }

        // done

        return verify;
    }

    @Override
    public boolean verify(byte[] signingInput, LdProof ldProof) throws GeneralSecurityException {

        return verify(signingInput, ldProof, this.getVerifier());
    }
}
