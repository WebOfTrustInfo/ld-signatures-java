package info.weboftrust.ldsignatures.verifier;

import java.security.GeneralSecurityException;
import java.text.ParseException;

import org.bitcoinj.core.ECKey;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.Payload;

import info.weboftrust.ldsignatures.LdSignature;
import info.weboftrust.ldsignatures.crypto.ByteVerifier;
import info.weboftrust.ldsignatures.crypto.adapter.JWSVerifierAdapter;
import info.weboftrust.ldsignatures.crypto.impl.P256K_ES256K_PublicKeyVerifier;
import info.weboftrust.ldsignatures.suites.EcdsaSecp256k1Signature2019SignatureSuite;
import info.weboftrust.ldsignatures.suites.SignatureSuites;
import info.weboftrust.ldsignatures.util.DetachedJWSObject;

public class EcdsaSecp256k1Signature2019LdVerifier extends LdVerifier<EcdsaSecp256k1Signature2019SignatureSuite> {

	public EcdsaSecp256k1Signature2019LdVerifier(ByteVerifier verifier) {

		super(SignatureSuites.SIGNATURE_SUITE_ECDSASECP256L1SIGNATURE2019, verifier);
	}

	public EcdsaSecp256k1Signature2019LdVerifier(ECKey publicKey) {

		this(new P256K_ES256K_PublicKeyVerifier(publicKey));
	}

	public EcdsaSecp256k1Signature2019LdVerifier() {

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

			JWSVerifier jwsVerifier = new JWSVerifierAdapter(verifier, JWSAlgorithm.ES256K);
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
		boolean verify = verifier.verify(canonicalizedDocumentBytes, signatureValueBytes, "ES256K");

		// done

		return verify;
	}*/

	@Override
	public boolean verify(String canonicalizedDocument, LdSignature ldSignature) throws GeneralSecurityException {

		return verify(canonicalizedDocument, ldSignature, this.getVerifier());
	}
}
