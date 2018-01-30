package info.weboftrust.ldsignatures;

import java.util.LinkedHashMap;

import com.github.jsonldjava.utils.JsonUtils;

import info.weboftrust.ldsignatures.util.CanonicalizationUtil;
import junit.framework.TestCase;

public class CanonicalizationTest extends TestCase {

	@SuppressWarnings("unchecked")
	public void testCanonicalizationInput() throws Exception {

		LinkedHashMap<String, Object> jsonLdObject = (LinkedHashMap<String, Object>) JsonUtils.fromInputStream(CanonicalizationTest.class.getResourceAsStream("input.jsonld"));
		String canonicalizedDocument = TestUtil.read(CanonicalizationTest.class.getResourceAsStream("input.canonicalized"));

		assertEquals(CanonicalizationUtil.buildCanonicalizedDocument(jsonLdObject), canonicalizedDocument);
	}

	@SuppressWarnings("unchecked")
	public void testCanonicalizationSigned() throws Exception {

		LinkedHashMap<String, Object> jsonLdObject = (LinkedHashMap<String, Object>) JsonUtils.fromInputStream(CanonicalizationTest.class.getResourceAsStream("signed.rsa.jsonld"));
		String canonicalizedDocument = TestUtil.read(CanonicalizationTest.class.getResourceAsStream("signed.rsa.canonicalized"));

		assertEquals(CanonicalizationUtil.buildCanonicalizedDocument(jsonLdObject), canonicalizedDocument);
	}
}
