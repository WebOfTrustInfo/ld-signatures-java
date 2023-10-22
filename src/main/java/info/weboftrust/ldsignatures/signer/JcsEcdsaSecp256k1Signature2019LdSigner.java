package info.weboftrust.ldsignatures.signer;

import com.danubetech.keyformats.crypto.ByteSigner;
import com.danubetech.keyformats.crypto.impl.secp256k1_ES256K_PrivateKeySigner;
import com.danubetech.keyformats.jose.JWSAlgorithm;
import info.weboftrust.ldsignatures.LdProof;
import info.weboftrust.ldsignatures.canonicalizer.JCSCanonicalizer;
import info.weboftrust.ldsignatures.suites.JcsEcdsaSecp256k1Signature2019SignatureSuite;
import info.weboftrust.ldsignatures.suites.SignatureSuites;
import io.ipfs.multibase.Base58;
import org.bitcoinj.core.ECKey;

import java.security.GeneralSecurityException;
import java.util.Map;

public class JcsEcdsaSecp256k1Signature2019LdSigner extends LdSigner<JcsEcdsaSecp256k1Signature2019SignatureSuite> {

    public JcsEcdsaSecp256k1Signature2019LdSigner(ByteSigner signer) {

        super(SignatureSuites.SIGNATURE_SUITE_JCSECDSASECP256L1SIGNATURE2019, signer, new JCSCanonicalizer());
    }

    public JcsEcdsaSecp256k1Signature2019LdSigner(ECKey privateKey) {

        this(new secp256k1_ES256K_PrivateKeySigner(privateKey));
    }

    public JcsEcdsaSecp256k1Signature2019LdSigner() {

        this((ByteSigner) null);
    }

    public static void sign(LdProof.Builder<? extends LdProof.Builder<?>> ldProofBuilder, byte[] signingInput, ByteSigner signer) throws GeneralSecurityException {

        // sign

        String signatureValue;

        byte[] bytes = signer.sign(signingInput, JWSAlgorithm.ES256K);
        signatureValue = Base58.encode(bytes);

        // done

        ldProofBuilder.properties(Map.of("signatureValue", signatureValue));
    }

    @Override
    public void sign(LdProof.Builder<? extends LdProof.Builder<?>> ldProofBuilder, byte[] signingInput) throws GeneralSecurityException {

        sign(ldProofBuilder, signingInput, this.getSigner());
    }
}
