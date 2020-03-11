package info.weboftrust.ldsignatures.verifier;

import java.security.GeneralSecurityException;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.JWSVerifier;

import info.weboftrust.ldsignatures.LdSignature;
import info.weboftrust.ldsignatures.crypto.ByteVerifier;
import info.weboftrust.ldsignatures.crypto.adapter.JWSVerifierAdapter;
import info.weboftrust.ldsignatures.crypto.impl.RSA_RS256_PublicKeyVerifier;
import info.weboftrust.ldsignatures.suites.RsaSignature2018SignatureSuite;
import info.weboftrust.ldsignatures.suites.SignatureSuites;
import info.weboftrust.ldsignatures.util.JWSUtil;

public class RsaSignature2018LdVerifier extends LdVerifier<RsaSignature2018SignatureSuite> {

	public RsaSignature2018LdVerifier(ByteVerifier verifier) {

		super(SignatureSuites.SIGNATURE_SUITE_RSASIGNATURE2018, verifier);
	}

	public RsaSignature2018LdVerifier(RSAPublicKey publicKey) {

		this(new RSA_RS256_PublicKeyVerifier(publicKey));
	}

	public RsaSignature2018LdVerifier() {

		this((ByteVerifier) null);
	}

	public static boolean verify(byte[] signingInput, LdSignature ldSignature, ByteVerifier verifier) throws GeneralSecurityException {

		// build the JWS and verify

		String jws = ldSignature.getJws();
		boolean verify;

		try {

			JWSObject detachedJwsObject = JWSObject.parse(jws);
			byte[] jwsSigningInput = JWSUtil.getJwsSigningInput(detachedJwsObject.getHeader(), signingInput);

			JWSVerifier jwsVerifier = new JWSVerifierAdapter(verifier, JWSAlgorithm.RS256);
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

	@Override
	public boolean verify(byte[] signingInput, LdSignature ldSignature) throws GeneralSecurityException {

		return verify(signingInput, ldSignature, this.getVerifier());
	}
}
