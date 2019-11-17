package info.weboftrust.ldsignatures.signer;

import java.security.GeneralSecurityException;
import java.security.interfaces.RSAPrivateKey;
import java.util.Collections;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.crypto.impl.RSASSAProvider;
import com.nimbusds.jose.util.Base64URL;

import info.weboftrust.ldsignatures.suites.RsaSignature2018SignatureSuite;
import info.weboftrust.ldsignatures.suites.SignatureSuites;

public class RsaSignature2018LdSigner extends LdSigner<RsaSignature2018SignatureSuite> {

	private Signer signer;

	public RsaSignature2018LdSigner(Signer signer) {

		super(SignatureSuites.SIGNATURE_SUITE_RSASIGNATURE2018);

		this.signer = signer;
	}

	public RsaSignature2018LdSigner(RSAPrivateKey privateKey) {

		this(new PrivateKeySigner(privateKey));
	}

	public RsaSignature2018LdSigner() {

		this((Signer) null);
	}

	public static String sign(String canonicalizedDocument, Signer signer) throws GeneralSecurityException {

		// build the payload

		String unencodedPayload = canonicalizedDocument;

		// build the JWS and sign

		String signatureValue;

		try {

			JWSHeader jwsHeader = new JWSHeader.Builder(JWSAlgorithm.RS256)
					.customParam("b64", Boolean.FALSE)
					.criticalParams(Collections.singleton("b64"))
					.build();

			Payload payload = new Payload(unencodedPayload);

			JWSObject jwsObject = new JWSObject(jwsHeader, payload);

			JWSSigner jwsSigner = new JWSSignerAdapter(signer);
			jwsObject.sign(jwsSigner);
			signatureValue = jwsObject.serialize(true);

			/*			JsonWebSignature jws = new JsonWebSignature();
			jws.setAlgorithmHeaderValue(AlgorithmIdentifiers.RSA_USING_SHA256);
			jws.getHeaders().setObjectHeaderValue(HeaderParameterNames.BASE64URL_ENCODE_PAYLOAD, false);
			jws.setCriticalHeaderNames(HeaderParameterNames.BASE64URL_ENCODE_PAYLOAD);
			jws.setPayload(unencodedPayload);

			jws.setKey(privateKey);
			signatureValue = jws.getDetachedContentCompactSerialization();*/
		} catch (JOSEException ex) {

			throw new GeneralSecurityException("JOSE signing problem: " + ex.getMessage(), ex);
		}

		// done

		return signatureValue;
	}

	@Override
	public String sign(String canonicalizedDocument) throws GeneralSecurityException {

		return sign(canonicalizedDocument, this.getSigner());
	}

	/*
	 * Helper class
	 */

	public interface Signer {

		public byte[] sign(String algorithm, byte[] content) throws GeneralSecurityException;
	}

	public static class PrivateKeySigner extends RSASSASigner implements Signer {

		public PrivateKeySigner(RSAPrivateKey privateKey) {

			super(privateKey);
		}

		public byte[] sign(String algorithm, byte[] content) throws GeneralSecurityException {

			JWSHeader jwsHeader = new JWSHeader(new JWSAlgorithm(algorithm));

			try {

				return super.sign(jwsHeader, content).decode();
			} catch (JOSEException ex) {

				throw new GeneralSecurityException(ex.getMessage(), ex);
			}
		}
	}

	private static class JWSSignerAdapter extends RSASSAProvider implements JWSSigner {

		private Signer signer;

		private JWSSignerAdapter(Signer signer) {

			this.signer = signer;
		}

		@Override
		public Base64URL sign(final JWSHeader header, final byte[] signingInput) throws JOSEException {

			String algorithm = header.getAlgorithm().getName();

			try {

				return Base64URL.encode(this.signer.sign(algorithm, signingInput));
			} catch (GeneralSecurityException ex) {

				throw new JOSEException(ex.getMessage(), ex);
			}
		}
	}

	/*
	 * Getters and setters
	 */

	public Signer getSigner() {

		return this.signer;
	}

	public void setSigner(Signer signer) {

		this.signer = signer;
	}
}
