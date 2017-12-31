package info.weboftrust.ldsignatures;

import java.util.LinkedHashMap;

import com.github.jsonldjava.utils.JsonUtils;

import info.weboftrust.ldsignatures.util.CanonicalizationUtil;
import junit.framework.TestCase;

public class CanonicalizationTest extends TestCase {

	@SuppressWarnings("unchecked")
	public void testCanonicalizationSign() throws Exception {

		LinkedHashMap<String, Object> jsonLdObject = (LinkedHashMap<String, Object>) JsonUtils.fromInputStream(CanonicalizationTest.class.getResourceAsStream("sign.test.jsonld"));
		String canonicalizedDocument = TestUtil.read(CanonicalizationTest.class.getResourceAsStream("sign.canonicalized.test"));

		assertEquals(CanonicalizationUtil.buildCanonicalizedDocument(jsonLdObject), canonicalizedDocument);
	}

	@SuppressWarnings("unchecked")
	public void testCanonicalizationValidate() throws Exception {

		LinkedHashMap<String, Object> jsonLdObject = (LinkedHashMap<String, Object>) JsonUtils.fromInputStream(CanonicalizationTest.class.getResourceAsStream("validate.test.jsonld"));
		String canonicalizedDocument = TestUtil.read(CanonicalizationTest.class.getResourceAsStream("validate.canonicalized.test"));

		assertEquals(CanonicalizationUtil.buildCanonicalizedDocument(jsonLdObject), canonicalizedDocument);
	}
}
