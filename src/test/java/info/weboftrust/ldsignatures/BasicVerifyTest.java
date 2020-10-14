package info.weboftrust.ldsignatures;

import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import info.weboftrust.ldsignatures.util.DetachedJWSObject;
import org.junit.jupiter.api.Test;

import java.util.Collections;

import static org.junit.jupiter.api.Assertions.assertTrue;

public class BasicVerifyTest {

	@Test
	public void testVerify() throws Exception {

		// build the payload

		String unencodedPayload = "$.02";

		// build the JWS and verify

		String signatureValue = "eyJjcml0IjpbImI2NCJdLCJiNjQiOmZhbHNlLCJhbGciOiJSUzI1NiJ9..XrdJ42-RRCvuErPRZvQ2NQ4d47npAGnTcM-bkgJHPYnLft08eLtICjqlfUPD31Kk1WO2HoPm6WfqEDhiq4-QGnm3mJ6YJfamGR5AJeP7guIdKR_m_-zuW8U-vXzzCTsiS6vSDG7lYVKjtE3rRYGyGFA1fGA-CgjkOkA3vD12EQcWMMqThP68jeH3j0cOoKgnvxnEL-EDZRzkbO2wARkiCBc11BJw6vDnn-WXe4xjvZTQpupbxDRT3BQG75oht_Ye9nc_J3vCJviRKItKAdfIOC0fjPJz9qcU4HMeSwqO-r3EchJV_kIJOLa5lU8Nq4L6DGGp1HOZb0neXIC9QHzkBA";

		boolean verify;

		Payload jwsPayload = new Payload(unencodedPayload);

		DetachedJWSObject jwsObject = DetachedJWSObject.parse(signatureValue, jwsPayload);

		JWSVerifier jwsVerifier = new RSASSAVerifier(TestUtil.testRSAPublicKey, Collections.singleton("b64"));
		verify = jwsVerifier.verify(jwsObject.getHeader(), jwsObject.getSigningInput(), jwsObject.getParsedSignature());

		// done

		assertTrue(verify);
	}
}
