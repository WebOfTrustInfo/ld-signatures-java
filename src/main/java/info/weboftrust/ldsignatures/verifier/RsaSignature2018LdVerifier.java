package info.weboftrust.ldsignatures.verifier;

import java.security.GeneralSecurityException;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;
import java.util.Collections;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.crypto.impl.RSASSAProvider;
import com.nimbusds.jose.util.Base64URL;

import info.weboftrust.ldsignatures.LdSignature;
import info.weboftrust.ldsignatures.suites.RsaSignature2018SignatureSuite;
import info.weboftrust.ldsignatures.suites.SignatureSuites;
import info.weboftrust.ldsignatures.util.DetachedJWSObject;

public class RsaSignature2018LdVerifier extends LdVerifier<RsaSignature2018SignatureSuite> {

	private Verifier verifier;

	public RsaSignature2018LdVerifier(Verifier verifier) {

		super(SignatureSuites.SIGNATURE_SUITE_RSASIGNATURE2018);

		this.verifier = verifier;
	}

	public RsaSignature2018LdVerifier(RSAPublicKey publicKey) {

		this(new PublicKeyVerifier(publicKey));
	}

	public RsaSignature2018LdVerifier() {

		this((Verifier) null);
	}

	public static boolean verify(String canonicalizedDocument, LdSignature ldSignature, Verifier verifier) throws GeneralSecurityException {

		// build the payload

		String unencodedPayload = canonicalizedDocument;

		// build the JWS and verify

		String signatureValue = ldSignature.getSignatureValue();
		boolean verify;

		try {

			Payload jwsPayload = new Payload(unencodedPayload);

			DetachedJWSObject jwsObject = DetachedJWSObject.parse(signatureValue, jwsPayload);

			JWSVerifier jwsVerifier = new JWSVerifierAdapter(verifier);
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
	 * Helper class
	 */

	public interface Verifier {

		public boolean verify(String algorithm, byte[] content, byte[] signature) throws GeneralSecurityException;
	}

	public static class PublicKeyVerifier extends RSASSAVerifier implements Verifier {

		public PublicKeyVerifier(RSAPublicKey publicKey) {

			super(publicKey, Collections.singleton("b64"));
		}

		@Override
		public boolean verify(String algorithm, byte[] content, byte[] signature) throws GeneralSecurityException {

			JWSHeader jwsHeader = new JWSHeader(new JWSAlgorithm(algorithm));

			try {

				return super.verify(jwsHeader, content, Base64URL.encode(signature));
			} catch (JOSEException ex) {

				throw new GeneralSecurityException(ex.getMessage(), ex);
			}
		}
	}

	private static class JWSVerifierAdapter extends RSASSAProvider implements JWSVerifier {

		private Verifier verifier;

		private JWSVerifierAdapter(Verifier verifier) {

			this.verifier = verifier;
		}

		@Override
		public boolean verify(JWSHeader header, byte[] signingInput, Base64URL signature) throws JOSEException {

			String algorithm = header.getAlgorithm().getName();

			try {

				return this.verifier.verify(algorithm, signingInput, signature.decode());
			} catch (GeneralSecurityException ex) {

				throw new JOSEException(ex.getMessage(), ex);
			}
		}
	}

	/*
	 * Getters and setters
	 */

	public Verifier getVerifier() {

		return this.verifier;
	}

	public void setVerifier(Verifier verifier) {

		this.verifier = verifier;
	}
}
