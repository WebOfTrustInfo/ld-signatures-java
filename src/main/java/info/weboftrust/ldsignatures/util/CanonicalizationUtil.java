package info.weboftrust.ldsignatures.util;

import com.github.jsonldjava.core.JsonLdError;
import com.github.jsonldjava.core.JsonLdOptions;
import com.github.jsonldjava.core.JsonLdProcessor;

public class CanonicalizationUtil {

	private CanonicalizationUtil() {

	}

	public static String buildCanonicalizedDocument(Object jsonLdObject) throws JsonLdError {

		// canonicalize the JSON-LD

		JsonLdOptions options = new JsonLdOptions();
		options.format = "application/nquads";
		String canonicalizedDocument = (String) JsonLdProcessor.normalize(jsonLdObject, options);

		// done

		return canonicalizedDocument;
	}
}
