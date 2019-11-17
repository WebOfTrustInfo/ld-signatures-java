package info.weboftrust.ldsignatures;

import java.util.Collections;

import org.jose4j.jwa.AlgorithmConstraints;
import org.jose4j.jws.AlgorithmIdentifiers;
import org.jose4j.jws.JsonWebSignature;

import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.RSASSAVerifier;

import info.weboftrust.ldsignatures.util.DetachedJWSObject;
import junit.framework.TestCase;

public class BasicVerifyTest extends TestCase {

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

		JsonWebSignature jws = new JsonWebSignature();
		jws.setAlgorithmConstraints(new AlgorithmConstraints(AlgorithmConstraints.ConstraintType.WHITELIST, AlgorithmIdentifiers.RSA_USING_SHA256));
		jws.setCompactSerialization("eyJhbGciOiJSUzI1NiIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..fZRkjTTrcXdUovHjghM6JvlMhJuR1s8X1F4Uy_F4oMhZ9KtF2Zp78lYSOI7OxB5uoTu8FpQHvy-dz3N4nLhoSWAi2_HrxZG_2DyctUUB_8pRKYBmIdIgpOlEMjIreOvXyM6A32gR-PdbzoQq14yQbbfxk12jyZSwcaNu29gXnW_uO7ku1GSV_juWE5E_yIstvEB1GG8ApUGIuzRJDrAAa8KBkHN7Rdfhc8rJMOeSZI0dc_A-Y7t0M0RtrgvV_FhzM40K1pwr1YUZ5y1N4QV13M5u5qJ_lBK40WtWYL5MbJ58Qqk_-Q8l1dp6OCmoMvwdc7FmMsPigmyklqo46uyjjw");
		jws.setPayload(unencodedPayload);

		jws.setKey(TestUtil.testRSAPublicKey);
		verify = jws.verifySignature();

		// done

		assertTrue(verify);
	}
}
