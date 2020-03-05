package info.weboftrust.ldsignatures.signer;

import java.net.URI;
import java.security.GeneralSecurityException;
import java.util.Date;
import java.util.LinkedHashMap;

import com.github.jsonldjava.core.JsonLdError;

import info.weboftrust.ldsignatures.LdSignature;
import info.weboftrust.ldsignatures.crypto.ByteSigner;
import info.weboftrust.ldsignatures.suites.SignatureSuite;
import info.weboftrust.ldsignatures.suites.SignatureSuites;
import info.weboftrust.ldsignatures.util.CanonicalizationUtil;
import info.weboftrust.ldsignatures.util.SHAUtil;

public abstract class LdSigner <SIGNATURESUITE extends SignatureSuite> {

	private final SIGNATURESUITE signatureSuite;

	private ByteSigner signer;

	private URI creator;
	private Date created;
	private String domain;
	private String nonce;
	private String proofPurpose;
	private String verificationMethod;

	protected LdSigner(SIGNATURESUITE signatureSuite, ByteSigner signer) {

		this.signatureSuite = signatureSuite;
		this.signer = signer;
	}

	protected LdSigner(SIGNATURESUITE signatureSuite, ByteSigner signer, URI creator, Date created, String domain, String nonce, String proofPurpose, String verificationMethod) {

		this.signatureSuite = signatureSuite;
		this.signer = signer;
		this.creator = creator;
		this.created = created;
		this.domain = domain;
		this.nonce = nonce;
		this.proofPurpose = proofPurpose;
		this.verificationMethod = verificationMethod;
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

	public abstract String sign(byte[] bytes) throws GeneralSecurityException;

	public LdSignature sign(LinkedHashMap<String, Object> jsonLdObject, boolean addToJsonLdObject, boolean addSecurityContext) throws JsonLdError, GeneralSecurityException {

		// build the signature object

		LdSignature ldSignature = new LdSignature();

		ldSignature.setType(this.getSignatureSuite().getTerm());
		if (this.getCreator() != null) ldSignature.setCreator(this.getCreator());
		if (this.getCreated() != null) ldSignature.setCreated(this.getCreated());
		if (this.getDomain() != null) ldSignature.setDomain(this.getDomain());
		if (this.getNonce() != null) ldSignature.setNonce(this.getNonce());
		if (this.getProofPurpose() != null) ldSignature.setProofPurpose(this.getProofPurpose());
		if (this.getVerificationMethod() != null) ldSignature.setVerificationMethod(this.getVerificationMethod());

		// obtain the canonicalized proof options

		LinkedHashMap<String, Object> jsonLdObjectProofOptions = new LinkedHashMap<String, Object> (ldSignature.getJsonLdSignatureObject());
		LdSignature.removeLdSignatureValues(jsonLdObjectProofOptions);
		LdSignature.addSecurityContextToJsonLdObject(jsonLdObjectProofOptions);
		String canonicalizedProofOptions = CanonicalizationUtil.buildCanonicalizedDocument(jsonLdObjectProofOptions);

		// obtain the canonicalized document

		LinkedHashMap<String, Object> jsonLdDocument = new LinkedHashMap<String, Object> (jsonLdObject);
		LdSignature.removeFromJsonLdObject(jsonLdDocument);
		String canonicalizedDocument = CanonicalizationUtil.buildCanonicalizedDocument(jsonLdDocument);

		// sign

		byte[] signingInput = new byte[64];
		System.arraycopy(SHAUtil.sha256(canonicalizedProofOptions), 0, signingInput, 0, 32);
		System.arraycopy(SHAUtil.sha256(canonicalizedDocument), 0, signingInput, 32, 32);

		String jws = this.sign(signingInput);
		ldSignature.setJws(jws);

		// add signature to JSON-LD?

		if (addToJsonLdObject) ldSignature.addToJsonLdObject(jsonLdObject, addSecurityContext);

		// done

		return ldSignature;
	}

	public LdSignature sign(LinkedHashMap<String, Object> jsonLdObject) throws JsonLdError, GeneralSecurityException {

		return sign(jsonLdObject, false, false);
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

	public Date getCreated() {
		return created;
	}

	public void setCreated(Date created) {
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

	public String getProofPurpose() {
		return proofPurpose;
	}

	public void setProofPurpose(String proofPurpose) {
		this.proofPurpose = proofPurpose;
	}

	public String getVerificationMethod() {
		return verificationMethod;
	}

	public void setVerificationMethod(String verificationMethod) {
		this.verificationMethod = verificationMethod;
	}
}
