package info.weboftrust.ldsignatures.canonicalizer;

import foundation.identity.jsonld.JsonLDException;
import foundation.identity.jsonld.JsonLDObject;
import info.weboftrust.ldsignatures.LdProof;
import info.weboftrust.ldsignatures.util.SHAUtil;

import java.io.IOException;
import java.security.GeneralSecurityException;

public class RdfCanonicalizer implements Canonicalizer {

    public static final String CANONICALIZATION_ALGORITH_URDNA2015 = "urdna2015";

    private String canonicalizationAlgorithm;

    public RdfCanonicalizer(String canonicalizationAlgorithm) {
        this.canonicalizationAlgorithm = canonicalizationAlgorithm;
    }

    public RdfCanonicalizer() {
        this(CANONICALIZATION_ALGORITH_URDNA2015);
    }

    @Override
    public byte[] canonicalize(LdProof ldProof, JsonLDObject jsonLdObject) throws IOException, GeneralSecurityException, JsonLDException {

        // construct the LD proof without proof values

        LdProof ldProofWithoutProofValues = LdProof.builder()
                .base(ldProof)
                .defaultContexts(true)
                .build();
        LdProof.removeLdProofValues(ldProofWithoutProofValues);

        // construct the LD object without proof

        JsonLDObject jsonLdObjectWithoutProof = JsonLDObject.builder()
                .base(jsonLdObject)
                .build();
        jsonLdObjectWithoutProof.setDocumentLoader(jsonLdObject.getDocumentLoader());
        LdProof.removeFromJsonLdObject(jsonLdObjectWithoutProof);

        // canonicalize the LD proof and LD object

        String canonicalizedLdProofWithoutProofValues = ldProofWithoutProofValues.normalize(this.getCanonicalizationAlgorithm());
        String canonicalizedJsonLdObjectWithoutProof = jsonLdObjectWithoutProof.normalize(this.getCanonicalizationAlgorithm());

        // construct the canonicalization result

        byte[] canonicalizationResult = new byte[64];
        System.arraycopy(SHAUtil.sha256(canonicalizedLdProofWithoutProofValues), 0, canonicalizationResult, 0, 32);
        System.arraycopy(SHAUtil.sha256(canonicalizedJsonLdObjectWithoutProof), 0, canonicalizationResult, 32, 32);

        return canonicalizationResult;
    }

    /*
     * Getters and setters
     */

    public String getCanonicalizationAlgorithm() {
        return canonicalizationAlgorithm;
    }

    public void setCanonicalizationAlgorithm(String canonicalizationAlgorithm) {
        this.canonicalizationAlgorithm = canonicalizationAlgorithm;
    }
}
