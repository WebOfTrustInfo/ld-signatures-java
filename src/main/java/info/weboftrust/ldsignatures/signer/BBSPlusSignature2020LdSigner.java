package info.weboftrust.ldsignatures.signer;

import com.danubetech.keyformats.jose.JWSAlgorithms;
import info.weboftrust.ldsignatures.LdProof;
import com.danubetech.keyformats.crypto.ByteSigner;
import com.danubetech.keyformats.crypto.impl.BLS12381_G2_BBSPlus_PrivateKeySigner;
import info.weboftrust.ldsignatures.suites.BBSPlusSignature2020SignatureSuite;
import info.weboftrust.ldsignatures.suites.SignatureSuites;
import io.ipfs.multibase.Multibase;
import org.bitcoinj.core.ECKey;

import java.security.GeneralSecurityException;

public class BBSPlusSignature2020LdSigner extends LdSigner<BBSPlusSignature2020SignatureSuite> {

    public BBSPlusSignature2020LdSigner(ByteSigner signer) {

        super(SignatureSuites.SIGNATURE_SUITE_BBSPLUSSIGNATURE2020, signer);
    }

    public BBSPlusSignature2020LdSigner(ECKey privateKey) {

        this(new BLS12381_G2_BBSPlus_PrivateKeySigner(privateKey));
    }

    public BBSPlusSignature2020LdSigner() {

        this((ByteSigner) null);
    }

    public static void sign(LdProof.Builder ldProofBuilder, byte[] signingInput, ByteSigner signer) throws GeneralSecurityException {

        // sign

        String proofValue;

        byte[] bytes = signer.sign(signingInput, JWSAlgorithms.BBSPlus.getName());
        proofValue = Multibase.encode(Multibase.Base.Base58BTC, bytes);

        // done

        ldProofBuilder.proofValue(proofValue);
    }

    @Override
    public void sign(LdProof.Builder ldProofBuilder, byte[] signingInput) throws GeneralSecurityException {

        sign(ldProofBuilder, signingInput, this.getSigner());
    }
}
