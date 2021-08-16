package info.weboftrust.ldsignatures.canonicalizer;

import foundation.identity.jsonld.JsonLDException;
import foundation.identity.jsonld.JsonLDObject;
import info.weboftrust.ldsignatures.LdProof;
import org.erdtman.jcs.JsonCanonicalizer;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.List;

public class JCSCanonicalizer extends Canonicalizer {

    public JCSCanonicalizer() {

        super(List.of("jcs"));
    }

    @Override
    public byte[] canonicalize(LdProof ldProof, JsonLDObject jsonLdObject) throws IOException, GeneralSecurityException, JsonLDException {

        // construct the LD proof without proof values

        LdProof ldProofWithoutProofValues = LdProof.builder()
                .base(ldProof)
                .defaultContexts(false)
                .build();
        LdProof.removeLdProofValues(ldProofWithoutProofValues);

        // construct the LD object with proof without proof values

        JsonLDObject jsonLdObjectWithProofWithoutProofValues = JsonLDObject.builder()
                .base(jsonLdObject)
                .build();
        jsonLdObjectWithProofWithoutProofValues.setDocumentLoader(jsonLdObject.getDocumentLoader());
        LdProof.removeFromJsonLdObject(jsonLdObjectWithProofWithoutProofValues);
        ldProofWithoutProofValues.addToJsonLDObject(jsonLdObjectWithProofWithoutProofValues);

        // canonicalize the LD object

        String canonicalizedJsonLdObjectWithProofWithoutProofValues = new JsonCanonicalizer(jsonLdObjectWithProofWithoutProofValues.toJson()).getEncodedString();

        // construct the canonicalization result

        byte[] canonicalizationResult = canonicalizedJsonLdObjectWithProofWithoutProofValues.getBytes();
        return canonicalizationResult;
    }
}
