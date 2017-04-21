package info.weboftrust.ldsignatures;

import org.jose4j.jws.AlgorithmIdentifiers;

import info.weboftrust.ldsignatures.jws.RFC7797JsonWebSignature;
import junit.framework.TestCase;

public class BasicSignTest extends TestCase {

	static String JWS_HEADER_STRING = "{\"alg\":\"RS256\",\"b64\":false,\"crit\":[\"b64\"]}";

	@Override
	protected void setUp() throws Exception {

	}

	@Override
	protected void tearDown() throws Exception {

	}

	public void testSign() throws Exception {

		// build the payload

		String unencodedPayload = "$.02";

		// build the JWS header and payload to be signed

		RFC7797JsonWebSignature jws = new RFC7797JsonWebSignature(JWS_HEADER_STRING, unencodedPayload);
		jws.setAlgorithmHeaderValue(AlgorithmIdentifiers.RSA_USING_SHA256);

		// sign the payload and build the JWS

		jws.setKey(TestUtil.testRSAPrivateKey);

		String signatureValue = jws.getDetachedContentCompactSerialization();

		// done

		assertEquals("eyJhbGciOiJSUzI1NiIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..fZRkjTTrcXdUovHjghM6JvlMhJuR1s8X1F4Uy_F4oMhZ9KtF2Zp78lYSOI7OxB5uoTu8FpQHvy-dz3N4nLhoSWAi2_HrxZG_2DyctUUB_8pRKYBmIdIgpOlEMjIreOvXyM6A32gR-PdbzoQq14yQbbfxk12jyZSwcaNu29gXnW_uO7ku1GSV_juWE5E_yIstvEB1GG8ApUGIuzRJDrAAa8KBkHN7Rdfhc8rJMOeSZI0dc_A-Y7t0M0RtrgvV_FhzM40K1pwr1YUZ5y1N4QV13M5u5qJ_lBK40WtWYL5MbJ58Qqk_-Q8l1dp6OCmoMvwdc7FmMsPigmyklqo46uyjjw", signatureValue);
	}
}
