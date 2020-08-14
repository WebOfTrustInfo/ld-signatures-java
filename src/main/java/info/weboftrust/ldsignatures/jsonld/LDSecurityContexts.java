package info.weboftrust.ldsignatures.jsonld;

import com.apicatalog.jsonld.api.JsonLdError;
import com.apicatalog.jsonld.document.JsonDocument;
import com.apicatalog.jsonld.http.media.MediaType;

import java.net.URI;
import java.util.HashMap;
import java.util.Map;

public class LDSecurityContexts {

    public static Map<URI, JsonDocument> CONTEXTS = new HashMap<URI, JsonDocument>();

    static {

        try {

            CONTEXTS.put(URI.create("https://w3id.org/security/v1"),
                    JsonDocument.of(MediaType.JSON_LD, JsonLDObject.class.getResourceAsStream("security-v1.jsonld")));
            CONTEXTS.put(URI.create("https://w3id.org/security/v2"),
                    JsonDocument.of(MediaType.JSON_LD, JsonLDObject.class.getResourceAsStream("security-v2.jsonld")));
            CONTEXTS.put(URI.create("https://w3id.org/security/v3"),
                    JsonDocument.of(MediaType.JSON_LD, JsonLDObject.class.getResourceAsStream("security-v3-unstable.jsonld")));

            for (Map.Entry<URI, JsonDocument> localCachedContext : CONTEXTS.entrySet()) {
                localCachedContext.getValue().setDocumentUrl(localCachedContext.getKey());
            }
        } catch (JsonLdError ex) {

            throw new ExceptionInInitializerError(ex);
        }
    }
}
