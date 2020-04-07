package info.weboftrust.ldsignatures;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.apache.commons.codec.binary.Hex;
import org.junit.jupiter.api.Test;

import info.weboftrust.ldsignatures.util.SHAUtil;

public class SHATest {

	@Test
	public void testSHA() throws Exception {

		String input = "$.02";

		assertEquals(Hex.encodeHexString(SHAUtil.sha256(input)), "0c294278d243b8bf2eb0d1681f00d6c6fda30286975038c394bd7cb7caffb197");
	}
}
