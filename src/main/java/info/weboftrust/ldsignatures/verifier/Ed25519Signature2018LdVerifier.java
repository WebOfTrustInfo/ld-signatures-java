package info.weboftrust.ldsignatures.verifier;

import java.security.GeneralSecurityException;
import java.text.ParseException;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.Payload;

import info.weboftrust.ldsignatures.LdSignature;
import info.weboftrust.ldsignatures.crypto.ByteVerifier;
import info.weboftrust.ldsignatures.crypto.adapter.JWSVerifierAdapter;
import info.weboftrust.ldsignatures.crypto.impl.Ed25519_EdDSA_PublicKeyVerifier;
import info.weboftrust.ldsignatures.suites.Ed25519Signature2018SignatureSuite;
import info.weboftrust.ldsignatures.suites.SignatureSuites;
import info.weboftrust.ldsignatures.util.DetachedJWSObject;

public class Ed25519Signature2018LdVerifier extends LdVerifier<Ed25519Signature2018SignatureSuite> {

	public Ed25519Signature2018LdVerifier(ByteVerifier verifier) {

		super(SignatureSuites.SIGNATURE_SUITE_ED25519SIGNATURE2018, verifier);
	}

	public Ed25519Signature2018LdVerifier(byte[] publicKey) {

		this(new Ed25519_EdDSA_PublicKeyVerifier(publicKey));
	}

	public Ed25519Signature2018LdVerifier() {

		this((ByteVerifier) null);
	}

	public static boolean verify(String canonicalizedDocument, LdSignature ldSignature, ByteVerifier verifier) throws GeneralSecurityException {

		// build the payload

		String unencodedPayload = canonicalizedDocument;

		// build the JWS and verify

		String jws = ldSignature.getJws();
		boolean verify;

		try {

			Payload jwsPayload = new Payload(unencodedPayload);

			DetachedJWSObject jwsObject = DetachedJWSObject.parse(jws, jwsPayload);

			JWSVerifier jwsVerifier = new JWSVerifierAdapter(verifier, JWSAlgorithm.EdDSA);
			verify = jwsVerifier.verify(jwsObject.getHeader(), jwsObject.getSigningInput(), jwsObject.getParsedSignature());

			/*			JsonWebSignature jws = new JsonWebSignature();
			jws.setAlgorithmConstraints(new AlgorithmConstraints(AlgorithmConstraints.ConstraintType.WHITELIST, AlgorithmIdentifiers.RSA_USING_SHA256));
			jws.setCompactSerialization(ldSignature.getJws());
			jws.setPayload(unencodedPayload);

			jws.setKey(publicKey);
			verify = jws.verifySignature();*/
		} catch (JOSEException | ParseException ex) {

			throw new GeneralSecurityException("JOSE verification problem: " + ex.getMessage(), ex);
		}

		// done

		return verify;
	}

	/*	public static boolean verify(String canonicalizedDocument, LdSignature ldSignature, ByteVerifier verifier) throws GeneralSecurityException {

		// verify

		byte[] canonicalizedDocumentBytes = canonicalizedDocument.getBytes(StandardCharsets.UTF_8);
		byte[] signatureValueBytes = Base64.decodeBase64(ldSignature.getJws());
		boolean verify = verifier.verify(canonicalizedDocumentBytes, signatureValueBytes, "EdDSA");

		// done

		return verify;
	}*/

	@Override
	public boolean verify(String canonicalizedDocument, LdSignature ldSignature) throws GeneralSecurityException {

		return verify(canonicalizedDocument, ldSignature, this.getVerifier());
	}
}
