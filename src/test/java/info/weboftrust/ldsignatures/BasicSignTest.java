package info.weboftrust.ldsignatures;

import org.jose4j.jws.AlgorithmIdentifiers;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwx.HeaderParameterNames;

import junit.framework.TestCase;

public class BasicSignTest extends TestCase {

	public void testSign() throws Exception {

		// build the payload

		String unencodedPayload = "$.02";

		// build the JWS header and sign

		String signatureValue;

		JsonWebSignature jws = new JsonWebSignature();
		jws.setAlgorithmHeaderValue(AlgorithmIdentifiers.RSA_USING_SHA256);
		jws.getHeaders().setObjectHeaderValue(HeaderParameterNames.BASE64URL_ENCODE_PAYLOAD, false);
		jws.setCriticalHeaderNames(HeaderParameterNames.BASE64URL_ENCODE_PAYLOAD);
		jws.setPayload(unencodedPayload);

		jws.setKey(TestUtil.testRSAPrivateKey);
		signatureValue = jws.getDetachedContentCompactSerialization();

		// done

		assertEquals("eyJhbGciOiJSUzI1NiIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..fZRkjTTrcXdUovHjghM6JvlMhJuR1s8X1F4Uy_F4oMhZ9KtF2Zp78lYSOI7OxB5uoTu8FpQHvy-dz3N4nLhoSWAi2_HrxZG_2DyctUUB_8pRKYBmIdIgpOlEMjIreOvXyM6A32gR-PdbzoQq14yQbbfxk12jyZSwcaNu29gXnW_uO7ku1GSV_juWE5E_yIstvEB1GG8ApUGIuzRJDrAAa8KBkHN7Rdfhc8rJMOeSZI0dc_A-Y7t0M0RtrgvV_FhzM40K1pwr1YUZ5y1N4QV13M5u5qJ_lBK40WtWYL5MbJ58Qqk_-Q8l1dp6OCmoMvwdc7FmMsPigmyklqo46uyjjw", signatureValue);
	}
}
