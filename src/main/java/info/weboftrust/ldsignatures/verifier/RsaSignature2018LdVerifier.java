package info.weboftrust.ldsignatures.verifier;

import java.security.GeneralSecurityException;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.Payload;

import info.weboftrust.ldsignatures.LdSignature;
import info.weboftrust.ldsignatures.crypto.ByteVerifier;
import info.weboftrust.ldsignatures.crypto.adapter.JWSVerifierAdapter;
import info.weboftrust.ldsignatures.crypto.impl.RSA_RS256_PublicKeyVerifier;
import info.weboftrust.ldsignatures.suites.RsaSignature2018SignatureSuite;
import info.weboftrust.ldsignatures.suites.SignatureSuites;
import info.weboftrust.ldsignatures.util.DetachedJWSObject;

public class RsaSignature2018LdVerifier extends LdVerifier<RsaSignature2018SignatureSuite> {

	private ByteVerifier verifier;

	public RsaSignature2018LdVerifier(ByteVerifier verifier) {

		super(SignatureSuites.SIGNATURE_SUITE_RSASIGNATURE2018);

		this.verifier = verifier;
	}

	public RsaSignature2018LdVerifier(RSAPublicKey publicKey) {

		this(new RSA_RS256_PublicKeyVerifier(publicKey));
	}

	public RsaSignature2018LdVerifier() {

		this((ByteVerifier) null);
	}

	public static boolean verify(String canonicalizedDocument, LdSignature ldSignature, ByteVerifier verifier) throws GeneralSecurityException {

		// build the payload

		String unencodedPayload = canonicalizedDocument;

		// build the JWS and verify

		String signatureValue = ldSignature.getSignatureValue();
		boolean verify;

		try {

			Payload jwsPayload = new Payload(unencodedPayload);

			DetachedJWSObject jwsObject = DetachedJWSObject.parse(signatureValue, jwsPayload);

			JWSVerifier jwsVerifier = new JWSVerifierAdapter(verifier, JWSAlgorithm.RS256);
			verify = jwsVerifier.verify(jwsObject.getHeader(), jwsObject.getSigningInput(), jwsObject.getParsedSignature());

/*			JsonWebSignature jws = new JsonWebSignature();
			jws.setAlgorithmConstraints(new AlgorithmConstraints(AlgorithmConstraints.ConstraintType.WHITELIST, AlgorithmIdentifiers.RSA_USING_SHA256));
			jws.setCompactSerialization(ldSignature.getSignatureValue());
			jws.setPayload(unencodedPayload);

			jws.setKey(publicKey);
			verify = jws.verifySignature();*/
		} catch (JOSEException | ParseException ex) {

			throw new GeneralSecurityException("JOSE verification problem: " + ex.getMessage(), ex);
		}

		// done

		return verify;
	}

	@Override
	public boolean verify(String canonicalizedDocument, LdSignature ldSignature) throws GeneralSecurityException {

		return verify(canonicalizedDocument, ldSignature, this.getVerifier());
	}

	/*
	 * Getters and setters
	 */

	public ByteVerifier getVerifier() {

		return this.verifier;
	}

	public void setVerifier(ByteVerifier verifier) {

		this.verifier = verifier;
	}
}
