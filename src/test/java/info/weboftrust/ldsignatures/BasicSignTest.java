package info.weboftrust.ldsignatures;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.Collections;

import org.junit.jupiter.api.Test;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.RSASSASigner;

public class BasicSignTest {

	@Test
	public void testSign() throws Exception {

		// build the payload

		String unencodedPayload = "$.02";

		// build the JWS header and sign

		String signatureValue;

		JWSHeader jwsHeader = new JWSHeader.Builder(JWSAlgorithm.RS256)
				.customParam("b64", Boolean.FALSE)
				.criticalParams(Collections.singleton("b64"))
				.build();

		Payload payload = new Payload(unencodedPayload);

		JWSObject jwsObject = new JWSObject(jwsHeader, payload);

		JWSSigner jwsSigner = new RSASSASigner(TestUtil.testRSAPrivateKey);
		jwsObject.sign(jwsSigner);
		signatureValue = jwsObject.serialize(true);

		/*
		JsonWebSignature jws = new JsonWebSignature();
		jws.setAlgorithmHeaderValue(AlgorithmIdentifiers.RSA_USING_SHA256);
		jws.getHeaders().setObjectHeaderValue(HeaderParameterNames.BASE64URL_ENCODE_PAYLOAD, false);
		jws.setCriticalHeaderNames(HeaderParameterNames.BASE64URL_ENCODE_PAYLOAD);
		jws.setPayload(unencodedPayload);

		jws.setKey(TestUtil.testRSAPrivateKey);
		signatureValue = jws.getDetachedContentCompactSerialization();*/

		// done

		assertEquals("eyJjcml0IjpbImI2NCJdLCJiNjQiOmZhbHNlLCJhbGciOiJSUzI1NiJ9..XrdJ42-RRCvuErPRZvQ2NQ4d47npAGnTcM-bkgJHPYnLft08eLtICjqlfUPD31Kk1WO2HoPm6WfqEDhiq4-QGnm3mJ6YJfamGR5AJeP7guIdKR_m_-zuW8U-vXzzCTsiS6vSDG7lYVKjtE3rRYGyGFA1fGA-CgjkOkA3vD12EQcWMMqThP68jeH3j0cOoKgnvxnEL-EDZRzkbO2wARkiCBc11BJw6vDnn-WXe4xjvZTQpupbxDRT3BQG75oht_Ye9nc_J3vCJviRKItKAdfIOC0fjPJz9qcU4HMeSwqO-r3EchJV_kIJOLa5lU8Nq4L6DGGp1HOZb0neXIC9QHzkBA", signatureValue);
	}
}
