package info.weboftrust.ldsignatures.verifier;

import com.danubetech.keyformats.crypto.ByteVerifier;
import com.danubetech.keyformats.crypto.impl.Ed25519_EdDSA_PublicKeyVerifier;
import com.danubetech.keyformats.jose.JWSAlgorithm;
import info.weboftrust.ldsignatures.LdProof;
import info.weboftrust.ldsignatures.canonicalizer.JCSCanonicalizer;
import info.weboftrust.ldsignatures.suites.JcsEd25519Signature2020SignatureSuite;
import info.weboftrust.ldsignatures.suites.SignatureSuites;
import io.ipfs.multibase.Base58;

import java.security.GeneralSecurityException;

public class JcsEd25519Signature2020LdVerifier extends LdVerifier<JcsEd25519Signature2020SignatureSuite> {

    public JcsEd25519Signature2020LdVerifier(ByteVerifier verifier) {

        super(SignatureSuites.SIGNATURE_SUITE_JCSED25519SIGNATURE2020, verifier, new JCSCanonicalizer());
    }

    public JcsEd25519Signature2020LdVerifier(byte[] publicKey) {

        this(new Ed25519_EdDSA_PublicKeyVerifier(publicKey));
    }

    public JcsEd25519Signature2020LdVerifier() {

        this((ByteVerifier) null);
    }

    public static boolean verify(byte[] signingInput, LdProof ldProof, ByteVerifier verifier) throws GeneralSecurityException {

        // verify

        String signatureValue = (String) ldProof.getJsonObject().get("signatureValue");
        if (signatureValue == null) throw new GeneralSecurityException("No 'signatureValue' in proof.");

        boolean verify;

        byte[] bytes = Base58.decode(signatureValue);
        verify = verifier.verify(signingInput, bytes, JWSAlgorithm.EdDSA);

        // done

        return verify;
    }

    @Override
    public boolean verify(byte[] signingInput, LdProof ldProof) throws GeneralSecurityException {

        return verify(signingInput, ldProof, this.getVerifier());
    }
}
