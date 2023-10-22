package info.weboftrust.ldsignatures.signer;

import com.danubetech.keyformats.crypto.ByteSigner;
import com.danubetech.keyformats.crypto.impl.RSA_RS256_PrivateKeySigner;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.util.Base64URL;
import info.weboftrust.ldsignatures.LdProof;
import info.weboftrust.ldsignatures.adapter.JWSSignerAdapter;
import info.weboftrust.ldsignatures.canonicalizer.URDNA2015Canonicalizer;
import info.weboftrust.ldsignatures.suites.RsaSignature2018SignatureSuite;
import info.weboftrust.ldsignatures.suites.SignatureSuites;
import info.weboftrust.ldsignatures.util.JWSUtil;

import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.util.Collections;

public class RsaSignature2018LdSigner extends LdSigner<RsaSignature2018SignatureSuite> {

    public RsaSignature2018LdSigner(ByteSigner signer) {

        super(SignatureSuites.SIGNATURE_SUITE_RSASIGNATURE2018, signer, new URDNA2015Canonicalizer());
    }

    public RsaSignature2018LdSigner(KeyPair privateKey) {

        this(new RSA_RS256_PrivateKeySigner(privateKey));
    }

    public RsaSignature2018LdSigner() {

        this((ByteSigner) null);
    }

    public static void sign(LdProof.Builder<? extends LdProof.Builder<?>> ldProofBuilder, byte[] signingInput, ByteSigner signer) throws GeneralSecurityException {

        // build the JWS and sign

        String jws;

        try {

            JWSHeader jwsHeader = new JWSHeader.Builder(JWSAlgorithm.RS256).base64URLEncodePayload(false).criticalParams(Collections.singleton("b64")).build();
            byte[] jwsSigningInput = JWSUtil.getJwsSigningInput(jwsHeader, signingInput);

            JWSSigner jwsSigner = new JWSSignerAdapter(signer, JWSAlgorithm.RS256);
            Base64URL signature = jwsSigner.sign(jwsHeader, jwsSigningInput);
            jws = JWSUtil.serializeDetachedJws(jwsHeader, signature);
        } catch (JOSEException ex) {

            throw new GeneralSecurityException("JOSE signing problem: " + ex.getMessage(), ex);
        }

        // done

        ldProofBuilder.jws(jws);
    }

    @Override
    public void sign(LdProof.Builder<? extends LdProof.Builder<?>> ldProofBuilder, byte[] signingInput) throws GeneralSecurityException {

        sign(ldProofBuilder, signingInput, this.getSigner());
    }
}
