package info.weboftrust.ldsignatures.signer;

import java.net.URI;
import java.security.GeneralSecurityException;
import java.util.LinkedHashMap;

import com.github.jsonldjava.core.JsonLdError;

import info.weboftrust.ldsignatures.LdSignature;
import info.weboftrust.ldsignatures.crypto.ByteSigner;
import info.weboftrust.ldsignatures.suites.SignatureSuite;
import info.weboftrust.ldsignatures.suites.SignatureSuites;
import info.weboftrust.ldsignatures.util.CanonicalizationUtil;

public abstract class LdSigner <SIGNATURESUITE extends SignatureSuite> {

	private final SIGNATURESUITE signatureSuite;

	private ByteSigner signer;

	private URI creator;
	private String created;
	private String domain;
	private String nonce;

	protected LdSigner(SIGNATURESUITE signatureSuite, ByteSigner signer) {

		this.signatureSuite = signatureSuite;
		this.signer = signer;
	}

	protected LdSigner(SIGNATURESUITE signatureSuite, ByteSigner signer, URI creator, String created, String domain, String nonce) {

		this.signatureSuite = signatureSuite;
		this.signer = signer;
		this.creator = creator;
		this.created = created;
		this.domain = domain;
		this.nonce = nonce;
	}

	public static LdSigner<? extends SignatureSuite> ldSignerForSignatureSuite(String signatureSuite) {

		if (SignatureSuites.SIGNATURE_SUITE_RSASIGNATURE2018.getTerm().equals(signatureSuite)) return new RsaSignature2018LdSigner();
		if (SignatureSuites.SIGNATURE_SUITE_ED25519SIGNATURE2018.getTerm().equals(signatureSuite)) return new Ed25519Signature2018LdSigner();
		if (SignatureSuites.SIGNATURE_SUITE_ECDSAKOBLITZSIGNATURE2016.getTerm().equals(signatureSuite)) return new EcdsaKoblitzSignature2016LdSigner();
		if (SignatureSuites.SIGNATURE_SUITE_ECDSASECP256L1SIGNATURE2019.getTerm().equals(signatureSuite)) return new EcdsaSecp256k1Signature2019LdSigner();

		throw new IllegalArgumentException();
	}

	public static LdSigner<? extends SignatureSuite> ldSignerForSignatureSuite(SignatureSuite signatureSuite) {

		return ldSignerForSignatureSuite(signatureSuite.getTerm());
	}

	public abstract String sign(String canonicalizedDocument) throws GeneralSecurityException;

	public LdSignature sign(LinkedHashMap<String, Object> jsonLdObject, boolean add) throws JsonLdError, GeneralSecurityException {

		// obtain the canonicalized document

		LinkedHashMap<String, Object> jsonLdObjectWithoutSignature = new LinkedHashMap<String, Object> (jsonLdObject);
		LdSignature.removeFromJsonLdObject(jsonLdObjectWithoutSignature);
		String canonicalizedDocument = CanonicalizationUtil.buildCanonicalizedDocument(jsonLdObjectWithoutSignature);

		// sign

		String signatureValue = this.sign(canonicalizedDocument);

		// build the signature object

		LdSignature ldSignature = new LdSignature();

		ldSignature.setType(this.getSignatureSuite().getTerm());
		ldSignature.setCreator(this.getCreator());
		ldSignature.setCreated(this.getCreated());
		ldSignature.setDomain(this.getDomain());
		ldSignature.setNonce(this.getNonce());
		ldSignature.setSignatureValue(signatureValue);

		// add signature to JSON-LD?

		if (add) ldSignature.addToJsonLdObject(jsonLdObject);

		// done

		return ldSignature;
	}

	public LdSignature sign(LinkedHashMap<String, Object> jsonLdObject) throws JsonLdError, GeneralSecurityException {

		return sign(jsonLdObject, true);
	}

	public SignatureSuite getSignatureSuite() {

		return this.signatureSuite;
	}

	/*
	 * Getters and setters
	 */

	public ByteSigner getSigner() {

		return this.signer;
	}

	public void setSigner(ByteSigner signer) {

		this.signer = signer;
	}

	public URI getCreator() {
		return creator;
	}

	public void setCreator(URI creator) {
		this.creator = creator;
	}

	public String getCreated() {
		return created;
	}

	public void setCreated(String created) {
		this.created = created;
	}

	public String getDomain() {
		return domain;
	}

	public void setDomain(String domain) {
		this.domain = domain;
	}

	public String getNonce() {
		return nonce;
	}

	public void setNonce(String nonce) {
		this.nonce = nonce;
	}
}
