package info.weboftrust.ldsignatures.verifier;

import com.danubetech.keyformats.crypto.ByteVerifier;
import com.danubetech.keyformats.crypto.impl.BLS12381_G2_BBSPlus_PublicKeyVerifier;
import com.danubetech.keyformats.jose.JWSAlgorithm;
import info.weboftrust.ldsignatures.LdProof;
import info.weboftrust.ldsignatures.suites.BBSPlusSignature2020SignatureSuite;
import info.weboftrust.ldsignatures.suites.SignatureSuites;
import io.ipfs.multibase.Multibase;
import org.bitcoinj.core.ECKey;

import java.security.GeneralSecurityException;

public class BBSPlusSignature2020LdVerifier extends LdVerifier<BBSPlusSignature2020SignatureSuite> {

    public BBSPlusSignature2020LdVerifier(ByteVerifier verifier) {

        super(SignatureSuites.SIGNATURE_SUITE_BBSPLUSSIGNATURE2020, verifier);
    }

    public BBSPlusSignature2020LdVerifier(ECKey publicKey) {

        this(new BLS12381_G2_BBSPlus_PublicKeyVerifier(publicKey));
    }

    public BBSPlusSignature2020LdVerifier() {

        this((ByteVerifier) null);
    }

    public static boolean verify(byte[] signingInput, LdProof ldProof, ByteVerifier verifier) throws GeneralSecurityException {

        // verify

        String proofValue = ldProof.getProofValue();
        boolean verify;

        byte[] bytes = Multibase.decode(proofValue);
        verify = verifier.verify(signingInput, bytes, JWSAlgorithm.BBSPlus);

        // done

        return verify;
    }

    @Override
    public boolean verify(byte[] signingInput, LdProof ldProof) throws GeneralSecurityException {

        return verify(signingInput, ldProof, this.getVerifier());
    }
}
