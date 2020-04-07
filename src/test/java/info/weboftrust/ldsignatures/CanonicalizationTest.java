package info.weboftrust.ldsignatures;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.LinkedHashMap;

import org.junit.jupiter.api.Test;

import com.github.jsonldjava.utils.JsonUtils;

import info.weboftrust.ldsignatures.util.CanonicalizationUtil;

public class CanonicalizationTest {

	@Test
	@SuppressWarnings("unchecked")
	public void testCanonicalizationInput() throws Exception {

		LinkedHashMap<String, Object> jsonLdObject = (LinkedHashMap<String, Object>) JsonUtils.fromInputStream(CanonicalizationTest.class.getResourceAsStream("input.jsonld"));
		String canonicalizedDocument = TestUtil.read(CanonicalizationTest.class.getResourceAsStream("input.canonicalized"));

		assertEquals(CanonicalizationUtil.buildCanonicalizedDocument(jsonLdObject), canonicalizedDocument);
	}

	/*
	@Test
	@SuppressWarnings("unchecked")
	public void testCanonicalizationFixImplicitGraph() throws Exception {

		LinkedHashMap<String, Object> jsonLdObject = (LinkedHashMap<String, Object>) JsonUtils.fromInputStream(CanonicalizationTest.class.getResourceAsStream("input.vc.jsonld"));
		String canonicalizedDocument = TestUtil.read(CanonicalizationTest.class.getResourceAsStream("input.vc.canonicalized"));

		CanonicalizationUtil.fixImplicitGraph(jsonLdObject, "proof");

		assertEquals(CanonicalizationUtil.buildCanonicalizedDocument(jsonLdObject), canonicalizedDocument);
	}*/

	@Test
	@SuppressWarnings("unchecked")
	public void testCanonicalizationSigned() throws Exception {

		LinkedHashMap<String, Object> jsonLdObject = (LinkedHashMap<String, Object>) JsonUtils.fromInputStream(CanonicalizationTest.class.getResourceAsStream("signed.rsa.jsonld"));
		String canonicalizedDocument = TestUtil.read(CanonicalizationTest.class.getResourceAsStream("signed.rsa.canonicalized"));

		assertEquals(CanonicalizationUtil.buildCanonicalizedDocument(jsonLdObject), canonicalizedDocument);
	}
}
