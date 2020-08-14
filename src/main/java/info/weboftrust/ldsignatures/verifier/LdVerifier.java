package info.weboftrust.ldsignatures.verifier;

import java.io.IOException;
import java.security.GeneralSecurityException;

import com.apicatalog.jsonld.api.JsonLdError;

import info.weboftrust.ldsignatures.LdSignature;
import info.weboftrust.ldsignatures.crypto.ByteVerifier;
import info.weboftrust.ldsignatures.jsonld.JsonLDObject;
import info.weboftrust.ldsignatures.jsonld.JsonLDUtils;
import info.weboftrust.ldsignatures.suites.SignatureSuite;
import info.weboftrust.ldsignatures.suites.SignatureSuites;
import info.weboftrust.ldsignatures.util.SHAUtil;

import javax.json.Json;

public abstract class LdVerifier <SIGNATURESUITE extends SignatureSuite> {

	private final SIGNATURESUITE signatureSuite;

	private ByteVerifier verifier;

	protected LdVerifier(SIGNATURESUITE signatureSuite, ByteVerifier verifier) {

		this.signatureSuite = signatureSuite;
		this.verifier = verifier;
	}

	public static LdVerifier<? extends SignatureSuite> ldVerifierForSignatureSuite(String signatureSuite) {

		if (SignatureSuites.SIGNATURE_SUITE_RSASIGNATURE2018.getTerm().equals(signatureSuite)) return new RsaSignature2018LdVerifier();
		if (SignatureSuites.SIGNATURE_SUITE_ED25519SIGNATURE2018.getTerm().equals(signatureSuite)) return new Ed25519Signature2018LdVerifier();
		if (SignatureSuites.SIGNATURE_SUITE_ECDSAKOBLITZSIGNATURE2016.getTerm().equals(signatureSuite)) return new EcdsaKoblitzSignature2016LdVerifier();
		if (SignatureSuites.SIGNATURE_SUITE_ECDSASECP256L1SIGNATURE2019.getTerm().equals(signatureSuite)) return new EcdsaSecp256k1Signature2019LdVerifier();

		throw new IllegalArgumentException();
	}

	public static LdVerifier<? extends SignatureSuite> ldVerifierForSignatureSuite(SignatureSuite signatureSuite) {

		return ldVerifierForSignatureSuite(signatureSuite.getTerm());
	}

	public abstract boolean verify(byte[] signingInput, LdSignature ldSignature) throws GeneralSecurityException;

	public boolean verify(JsonLDObject jsonLdObject, LdSignature ldSignature) throws GeneralSecurityException, IOException, JsonLdError {

		// check the signature object

		if (! this.getSignatureSuite().getTerm().equals(ldSignature.getType())) throw new GeneralSecurityException("Unexpected signature type: " + ldSignature.getType() + " is not " + this.getSignatureSuite().getTerm());

		// obtain the canonicalized proof options

		JsonLDObject jsonLdObjectProofOptions = JsonLDObject.builder().contexts(LdSignature.DEFAULT_CONTEXTS).build();
		JsonLDUtils.jsonLdAddAll(jsonLdObjectProofOptions.getJsonObjectBuilder(), ldSignature.getJsonObject());
		LdSignature.removeLdProofValues(jsonLdObjectProofOptions);
		String canonicalizedProofOptions = jsonLdObjectProofOptions.toRDF();

		// obtain the canonicalized document

		JsonLDObject jsonLdDocumentWithoutProof = JsonLDObject.builder().build();
		JsonLDUtils.jsonLdAddAll(jsonLdDocumentWithoutProof.getJsonObjectBuilder(), jsonLdObject.getJsonObject());
		LdSignature.removeFromJsonLdObject(jsonLdDocumentWithoutProof);
		String canonicalizedDocument = jsonLdDocumentWithoutProof.toRDF();

		// verify

		byte[] signingInput = new byte[64];
		System.arraycopy(SHAUtil.sha256(canonicalizedProofOptions), 0, signingInput, 0, 32);
		System.arraycopy(SHAUtil.sha256(canonicalizedDocument), 0, signingInput, 32, 32);

		boolean verify = this.verify(signingInput, ldSignature);

		// done

		return verify;
	}

	public boolean verify(JsonLDObject jsonLdObject) throws GeneralSecurityException, IOException, JsonLdError {

		// obtain the signature object

		LdSignature ldSignature = LdSignature.getFromJsonLdObject(jsonLdObject);
		if (ldSignature == null) return false;

		// done

		return this.verify(jsonLdObject, ldSignature);
	}

	public SignatureSuite getSignatureSuite() {

		return this.signatureSuite;
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
