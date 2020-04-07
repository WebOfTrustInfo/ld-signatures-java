package info.weboftrust.ldsignatures.verifier;

import java.security.GeneralSecurityException;
import java.text.ParseException;

import org.bitcoinj.core.ECKey;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.JWSVerifier;

import info.weboftrust.ldsignatures.LdSignature;
import info.weboftrust.ldsignatures.crypto.ByteVerifier;
import info.weboftrust.ldsignatures.crypto.adapter.JWSVerifierAdapter;
import info.weboftrust.ldsignatures.crypto.impl.secp256k1_ES256K_PublicKeyVerifier;
import info.weboftrust.ldsignatures.suites.EcdsaKoblitzSignature2016SignatureSuite;
import info.weboftrust.ldsignatures.suites.SignatureSuites;
import info.weboftrust.ldsignatures.util.JWSUtil;

public class EcdsaKoblitzSignature2016LdVerifier extends LdVerifier<EcdsaKoblitzSignature2016SignatureSuite> {

	public EcdsaKoblitzSignature2016LdVerifier(ByteVerifier verifier) {

		super(SignatureSuites.SIGNATURE_SUITE_ECDSAKOBLITZSIGNATURE2016, verifier);
	}

	public EcdsaKoblitzSignature2016LdVerifier(ECKey publicKey) {

		this(new secp256k1_ES256K_PublicKeyVerifier(publicKey));
	}

	public EcdsaKoblitzSignature2016LdVerifier() {

		this((ByteVerifier) null);
	}

	public static boolean verify(byte[] signingInput, LdSignature ldSignature, ByteVerifier verifier) throws GeneralSecurityException {

		// build the JWS and verify

		String jws = ldSignature.getJws();
		boolean verify;

		try {

			JWSObject detachedJwsObject = JWSObject.parse(jws);
			byte[] jwsSigningInput = JWSUtil.getJwsSigningInput(detachedJwsObject.getHeader(), signingInput);

			JWSVerifier jwsVerifier = new JWSVerifierAdapter(verifier, JWSAlgorithm.ES256K);
			verify = jwsVerifier.verify(detachedJwsObject.getHeader(), jwsSigningInput, detachedJwsObject.getSignature());

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
	public boolean verify(byte[] signingInput, LdSignature ldSignature) throws GeneralSecurityException {

		return verify(signingInput, ldSignature, this.getVerifier());
	}
}
