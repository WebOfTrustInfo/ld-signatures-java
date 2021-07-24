package info.weboftrust.ldsignatures.verifier;

import com.danubetech.keyformats.crypto.ByteVerifier;
import com.danubetech.keyformats.crypto.impl.secp256k1_ES256K_PublicKeyVerifier;
import com.danubetech.keyformats.jose.JWSAlgorithm;
import info.weboftrust.ldsignatures.LdProof;
import info.weboftrust.ldsignatures.canonicalizer.JCSCanonicalizer;
import info.weboftrust.ldsignatures.suites.JcsEcdsaSecp256k1Signature2019SignatureSuite;
import info.weboftrust.ldsignatures.suites.SignatureSuites;
import io.ipfs.multibase.Base58;
import org.bitcoinj.core.ECKey;

import java.security.GeneralSecurityException;

public class JcsEcdsaSecp256k1Signature2019LdVerifier extends LdVerifier<JcsEcdsaSecp256k1Signature2019SignatureSuite> {

    public JcsEcdsaSecp256k1Signature2019LdVerifier(ByteVerifier verifier) {

        super(SignatureSuites.SIGNATURE_SUITE_JCSECDSASECP256L1SIGNATURE2019, verifier, new JCSCanonicalizer());
    }

    public JcsEcdsaSecp256k1Signature2019LdVerifier(ECKey publicKey) {

        this(new secp256k1_ES256K_PublicKeyVerifier(publicKey));
    }

    public JcsEcdsaSecp256k1Signature2019LdVerifier() {

        this((ByteVerifier) null);
    }

    public static boolean verify(byte[] signingInput, LdProof ldProof, ByteVerifier verifier) throws GeneralSecurityException {

        // verify

        String signatureValue = (String) ldProof.getJsonObject().get("signatureValue");
        if (signatureValue == null) throw new GeneralSecurityException("No 'signatureValue' in proof.");

        boolean verify;

        byte[] bytes = Base58.decode(signatureValue);
        verify = verifier.verify(signingInput, bytes, JWSAlgorithm.ES256K);

        // done

        return verify;
    }

    @Override
    public boolean verify(byte[] signingInput, LdProof ldProof) throws GeneralSecurityException {

        return verify(signingInput, ldProof, this.getVerifier());
    }
}
