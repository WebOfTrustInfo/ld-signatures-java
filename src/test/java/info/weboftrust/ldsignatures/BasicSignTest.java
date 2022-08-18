package info.weboftrust.ldsignatures;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.RSASSASigner;
import org.junit.jupiter.api.Test;

import java.util.Collections;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class BasicSignTest {

	@Test
	public void testSign() throws Exception {

		// build the payload

		String unencodedPayload = "$.02";

		// build the JWS header and sign

		String signatureValue;

		JWSHeader jwsHeader = new JWSHeader.Builder(JWSAlgorithm.RS256)
				.base64URLEncodePayload(false)
				.criticalParams(Collections.singleton("b64"))
				.build();

		Payload payload = new Payload(unencodedPayload);

		JWSObject jwsObject = new JWSObject(jwsHeader, payload);

		JWSSigner jwsSigner = new RSASSASigner(TestUtil.testRSAPrivateKey.getPrivate());
		jwsObject.sign(jwsSigner);
		signatureValue = jwsObject.serialize(true);

		// done

		assertEquals("eyJiNjQiOmZhbHNlLCJjcml0IjpbImI2NCJdLCJhbGciOiJSUzI1NiJ9..tV8_yJKmBG6Efl6tQSW-0I3h1yubQAez3FMYuBg57oloZ8EdMZJ7EcHiyreNgXbRhJZ55bp92UwNUA98INACJvqrykm_-mwmEtltrHM6GkijyufyEOPMVh9JOlvVps7oS8h1EftlX6tvwYBhmn9iHGxOcYJvrJPbWDVt3rPRJf7Mn_wdGodFuZMCPKhEcserC6-xUSeV_aZTKHBklNbkNmL3Q1nbcTQvrMg4RLKwf4X6y3QRvb1vd0BAfmqA0H5HJ2ZAHvCLxIPlUHz8DN7kCRJa8lzoIbb4mAyYa8MAVgeuSyHJ89kF5UOZtVsMQayW6St2dSQR27dv3e4zRgk1Ig", signatureValue);
	}
}
