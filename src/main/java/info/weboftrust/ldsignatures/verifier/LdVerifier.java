package info.weboftrust.ldsignatures.verifier;

import com.danubetech.keyformats.crypto.ByteVerifier;
import foundation.identity.jsonld.JsonLDException;
import foundation.identity.jsonld.JsonLDObject;
import info.weboftrust.ldsignatures.LdProof;
import info.weboftrust.ldsignatures.suites.SignatureSuite;
import info.weboftrust.ldsignatures.util.SHAUtil;

import java.io.IOException;
import java.security.GeneralSecurityException;

public abstract class LdVerifier<SIGNATURESUITE extends SignatureSuite> {

    private final SIGNATURESUITE signatureSuite;

    private ByteVerifier verifier;

    protected LdVerifier(SIGNATURESUITE signatureSuite, ByteVerifier verifier) {

        this.signatureSuite = signatureSuite;
        this.verifier = verifier;
    }

    public static LdVerifier<? extends SignatureSuite> ldVerifierForSignatureSuite(String signatureSuiteTerm) {
        return LdVerifierRegistry.getLdVerifierBySignatureSuiteTerm(signatureSuiteTerm);
    }

    public static LdVerifier<? extends SignatureSuite> ldVerifierForSignatureSuite(SignatureSuite signatureSuite) {
        return ldVerifierForSignatureSuite(signatureSuite.getTerm());
    }

    public abstract boolean verify(byte[] signingInput, LdProof ldProof) throws GeneralSecurityException;

    public boolean verify(JsonLDObject jsonLdObject, LdProof ldProof) throws IOException, GeneralSecurityException, JsonLDException {

        // check the proof object

        if (!this.getSignatureSuite().getTerm().equals(ldProof.getType()))
            throw new GeneralSecurityException("Unexpected signature type: " + ldProof.getType() + " is not " + this.getSignatureSuite().getTerm());

        // obtain the normalized proof options

        JsonLDObject jsonLdObjectProofOptions = LdProof.builder()
                .defaultContexts(true)
                .base(ldProof)
                .build();
        LdProof.removeLdProofValues(jsonLdObjectProofOptions);
        String normalizedProofOptions = jsonLdObjectProofOptions.normalize("urdna2015");

        // obtain the normalized document

        JsonLDObject jsonLdDocumentWithoutProof = JsonLDObject.builder()
                .base(jsonLdObject)
                .build();
        jsonLdDocumentWithoutProof.setDocumentLoader(jsonLdObject.getDocumentLoader());
        LdProof.removeFromJsonLdObject(jsonLdDocumentWithoutProof);
        String normalizedDocument = jsonLdDocumentWithoutProof.normalize("urdna2015");

        // verify

        byte[] signingInput = new byte[64];
        System.arraycopy(SHAUtil.sha256(normalizedProofOptions), 0, signingInput, 0, 32);
        System.arraycopy(SHAUtil.sha256(normalizedDocument), 0, signingInput, 32, 32);

        boolean verify = this.verify(signingInput, ldProof);

        // done

        return verify;
    }

    public boolean verify(JsonLDObject jsonLdObject) throws IOException, GeneralSecurityException, JsonLDException {

        // obtain the signature object

        LdProof ldProof = LdProof.getFromJsonLDObject(jsonLdObject);
        if (ldProof == null) return false;

        // done

        return this.verify(jsonLdObject, ldProof);
    }

    public SignatureSuite getSignatureSuite() {

        return this.signatureSuite;
    }

    /*
     * Getters and setters
     */

    public ByteVerifier getVerifier() {

        return this.verifier;
    }

    public void setVerifier(ByteVerifier verifier) {

        this.verifier = verifier;
    }
}
