package info.weboftrust.ldsignatures.signer;

import java.security.GeneralSecurityException;
import java.util.Collections;

import org.bitcoinj.core.ECKey;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.Payload;

import info.weboftrust.ldsignatures.crypto.ByteSigner;
import info.weboftrust.ldsignatures.crypto.adapter.JWSSignerAdapter;
import info.weboftrust.ldsignatures.crypto.impl.P256K_ES256K_PrivateKeySigner;
import info.weboftrust.ldsignatures.suites.EcdsaKoblitzSignature2016SignatureSuite;
import info.weboftrust.ldsignatures.suites.SignatureSuites;

public class EcdsaKoblitzSignature2016LdSigner extends LdSigner<EcdsaKoblitzSignature2016SignatureSuite> {

	public EcdsaKoblitzSignature2016LdSigner(ByteSigner signer) {

		super(SignatureSuites.SIGNATURE_SUITE_ECDSAKOBLITZSIGNATURE2016, signer);
	}

	public EcdsaKoblitzSignature2016LdSigner(ECKey privateKey) {

		this(new P256K_ES256K_PrivateKeySigner(privateKey));
	}

	public EcdsaKoblitzSignature2016LdSigner() {

		this((ByteSigner) null);
	}

	public static String sign(String canonicalizedDocument, ByteSigner signer) throws GeneralSecurityException {

		// build the payload

		String unencodedPayload = canonicalizedDocument;

		// build the JWS and sign

		String jws;

		try {

			JWSHeader jwsHeader = new JWSHeader.Builder(JWSAlgorithm.ES256K)
					.customParam("b64", Boolean.FALSE)
					.criticalParams(Collections.singleton("b64"))
					.build();

			Payload payload = new Payload(unencodedPayload);

			JWSObject jwsObject = new JWSObject(jwsHeader, payload);

			JWSSigner jwsSigner = new JWSSignerAdapter(signer, JWSAlgorithm.ES256);
			jwsObject.sign(jwsSigner);
			jws = jwsObject.serialize(true);

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

		return jws;
	}

	/*	public static String sign(String canonicalizedDocument, ByteSigner signer) throws GeneralSecurityException {

		// sign

		byte[] canonicalizedDocumentBytes = canonicalizedDocument.getBytes(StandardCharsets.UTF_8);
		byte[] signatureBytes = signer.sign(canonicalizedDocumentBytes, "ES256K");
		String signatureString = Base64.encodeBase64String(signatureBytes);

		// done

		return signatureString;
	}*/

	@Override
	public String sign(String canonicalizedDocument) throws GeneralSecurityException {

		return sign(canonicalizedDocument, this.getSigner());
	}
}
