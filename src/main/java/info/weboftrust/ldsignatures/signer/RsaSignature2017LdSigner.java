package info.weboftrust.ldsignatures.signer;

import java.net.URI;
import java.security.interfaces.RSAPrivateKey;
import java.text.ParseException;
import java.util.LinkedHashMap;

import org.jose4j.jws.AlgorithmIdentifiers;
import org.jose4j.lang.JoseException;

import com.github.jsonldjava.core.JsonLdError;

import info.weboftrust.ldsignatures.LdSignature;
import info.weboftrust.ldsignatures.jws.RFC7797JsonWebSignature;
import info.weboftrust.ldsignatures.suites.RsaSignature2017SignatureSuite;
import info.weboftrust.ldsignatures.suites.SignatureSuites;
import info.weboftrust.ldsignatures.util.CanonicalizationUtil;

public class RsaSignature2017LdSigner extends LdSigner<RsaSignature2017SignatureSuite> {

	static String JWS_HEADER_STRING = "{\"alg\":\"RS256\",\"b64\":false,\"crit\":[\"b64\"]}";

	private LinkedHashMap<String, Object> jsonLdObject;
	private RSAPrivateKey privateKey;

	public RsaSignature2017LdSigner(LinkedHashMap<String, Object> jsonLdObject, RSAPrivateKey privateKey, URI creator, String created, String domain, String nonce) {

		super(creator, created, domain, nonce);

		this.jsonLdObject = jsonLdObject;
		this.privateKey = privateKey;
	}

	public String buildCanonicalizedDocument() throws JsonLdError {

		return CanonicalizationUtil.buildCanonicalizedDocument(this.jsonLdObject);
	}

	public static String buildSignatureValue(String canonicalizedDocument, RSAPrivateKey privateKey) throws JsonLdError, ParseException, JoseException {

		// build the payload

		String unencodedPayload = canonicalizedDocument;

		// build the JWS header and payload to be signed

		RFC7797JsonWebSignature jws = new RFC7797JsonWebSignature(JWS_HEADER_STRING, unencodedPayload);
		jws.setAlgorithmHeaderValue(AlgorithmIdentifiers.RSA_USING_SHA256);

		// sign the payload and build the JWS

		jws.setKey(privateKey);

		String signatureValue = jws.getDetachedContentCompactSerialization();

		// done

		return signatureValue;
	}

	public String buildSignatureValue() throws JsonLdError, ParseException, JoseException {

		String canonicalizedDocument = this.buildCanonicalizedDocument();

		return buildSignatureValue(canonicalizedDocument, this.privateKey);
	}

	public static LdSignature buildLdSignature(String signatureValue, URI creator, String created, String domain, String nonce) {

		// build the JSON-LD signature object

		LdSignature ldSignature = new LdSignature();
		ldSignature.setType(SignatureSuites.SIGNATURE_SUITE_RSASIGNATURE2017.getId());
		ldSignature.setCreator(creator);
		ldSignature.setCreated(created);
		ldSignature.setDomain(domain);
		ldSignature.setNonce(nonce);
		ldSignature.setSignatureValue(signatureValue);

		// done

		return ldSignature;
	}

	public LdSignature buildLdSignature() throws JsonLdError, ParseException, JoseException {

		String signatureValue = this.buildSignatureValue();

		return buildLdSignature(signatureValue, this.creator, this.created, this.domain, this.nonce);
	}

	public void sign() throws JsonLdError, ParseException, JoseException {

		LdSignature ldSignature = this.buildLdSignature();

		ldSignature.addToJsonLdObject(this.jsonLdObject);
	}
}
