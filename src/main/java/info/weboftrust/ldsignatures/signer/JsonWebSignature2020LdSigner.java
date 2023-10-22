package info.weboftrust.ldsignatures.signer;

import com.danubetech.keyformats.crypto.ByteSigner;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.util.Base64URL;
import info.weboftrust.ldsignatures.LdProof;
import info.weboftrust.ldsignatures.adapter.JWSSignerAdapter;
import info.weboftrust.ldsignatures.canonicalizer.URDNA2015Canonicalizer;
import info.weboftrust.ldsignatures.suites.JsonWebSignature2020SignatureSuite;
import info.weboftrust.ldsignatures.suites.SignatureSuites;
import info.weboftrust.ldsignatures.util.JWSUtil;

import java.security.GeneralSecurityException;
import java.util.Collections;

public class JsonWebSignature2020LdSigner extends LdSigner<JsonWebSignature2020SignatureSuite> {

    public JsonWebSignature2020LdSigner(ByteSigner signer) {

        super(SignatureSuites.SIGNATURE_SUITE_JSONWEBSIGNATURE2020, signer, new URDNA2015Canonicalizer());
    }

    public JsonWebSignature2020LdSigner() {

        this(null);
    }

    public static void sign(LdProof.Builder<? extends LdProof.Builder<?>> ldProofBuilder, byte[] signingInput, ByteSigner signer) throws GeneralSecurityException {

        // build the JWS and sign

        String jws;

        try {

            JWSHeader jwsHeader = new JWSHeader.Builder(JWSAlgorithm.parse(signer.getAlgorithm())).base64URLEncodePayload(false).criticalParams(Collections.singleton("b64")).build();
            byte[] jwsSigningInput = JWSUtil.getJwsSigningInput(jwsHeader, signingInput);

            JWSSigner jwsSigner = new JWSSignerAdapter(signer, JWSAlgorithm.parse(signer.getAlgorithm()));
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
