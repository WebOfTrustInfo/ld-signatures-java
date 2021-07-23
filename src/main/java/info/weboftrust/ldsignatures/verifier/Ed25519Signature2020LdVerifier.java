package info.weboftrust.ldsignatures.verifier;

import com.danubetech.keyformats.crypto.ByteVerifier;
import com.danubetech.keyformats.crypto.impl.Ed25519_EdDSA_PublicKeyVerifier;
import com.danubetech.keyformats.jose.JWSAlgorithm;
import info.weboftrust.ldsignatures.LdProof;
import info.weboftrust.ldsignatures.canonicalizer.URDNA2015Canonicalizer;
import info.weboftrust.ldsignatures.suites.Ed25519Signature2020SignatureSuite;
import info.weboftrust.ldsignatures.suites.SignatureSuites;
import io.ipfs.multibase.Multibase;

import java.security.GeneralSecurityException;

public class Ed25519Signature2020LdVerifier extends LdVerifier<Ed25519Signature2020SignatureSuite> {

    public Ed25519Signature2020LdVerifier(ByteVerifier verifier) {

        super(SignatureSuites.SIGNATURE_SUITE_ED25519SIGNATURE2020, verifier, new URDNA2015Canonicalizer());
    }

    public Ed25519Signature2020LdVerifier(byte[] publicKey) {

        this(new Ed25519_EdDSA_PublicKeyVerifier(publicKey));
    }

    public Ed25519Signature2020LdVerifier() {

        this((ByteVerifier) null);
    }

    public static boolean verify(byte[] signingInput, LdProof ldProof, ByteVerifier verifier) throws GeneralSecurityException {

        // verify

        String proofValue = ldProof.getProofValue();
        if (proofValue == null) throw new GeneralSecurityException("No 'proofValue' in proof.");

        boolean verify;

        byte[] bytes = Multibase.decode(proofValue);
        verify = verifier.verify(signingInput, bytes, JWSAlgorithm.EdDSA);

        // done

        return verify;
    }

    @Override
    public boolean verify(byte[] signingInput, LdProof ldProof) throws GeneralSecurityException {

        return verify(signingInput, ldProof, this.getVerifier());
    }
}
