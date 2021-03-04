package info.weboftrust.ldsignatures.signer;

import foundation.identity.jsonld.JsonLDException;
import foundation.identity.jsonld.JsonLDObject;
import foundation.identity.jsonld.JsonLDUtils;
import info.weboftrust.ldsignatures.LdProof;
import info.weboftrust.ldsignatures.crypto.ByteSigner;
import info.weboftrust.ldsignatures.suites.SignatureSuite;
import info.weboftrust.ldsignatures.suites.SignatureSuites;
import info.weboftrust.ldsignatures.util.SHAUtil;

import java.io.IOException;
import java.net.URI;
import java.security.GeneralSecurityException;
import java.util.Date;
import java.util.Map;

public abstract class LdSigner <SIGNATURESUITE extends SignatureSuite> {

	private final SIGNATURESUITE signatureSuite;

	private ByteSigner signer;

	private URI creator;
	private Date created;
	private String domain;
	private String nonce;
	private String proofPurpose;
	private URI verificationMethod;

	protected LdSigner(SIGNATURESUITE signatureSuite, ByteSigner signer) {

		this.signatureSuite = signatureSuite;
		this.signer = signer;
	}

	protected LdSigner(SIGNATURESUITE signatureSuite, ByteSigner signer, URI creator, Date created, String domain, String nonce, String proofPurpose, String URI) {

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

	public abstract void sign(LdProof.Builder ldProofBuilder, byte[] signingInput) throws GeneralSecurityException;

	public LdProof sign(JsonLDObject jsonLdObject, boolean addToJsonLdObject, boolean defaultContexts) throws IOException, GeneralSecurityException, JsonLDException {

		// build the proof object

		LdProof ldProofWithoutProofValues = LdProof.builder()
				.defaultContexts(false)
				.defaultTypes(false)
				.type(this.getSignatureSuite().getTerm())
				.creator(this.getCreator())
				.created(this.getCreated())
				.domain(this.getDomain())
				.nonce(this.getNonce())
				.proofPurpose(this.getProofPurpose())
				.verificationMethod(this.getVerificationMethod())
				.build();

		// obtain the normalized proof options

		JsonLDObject jsonLdObjectProofOptions = LdProof.builder()
				.base(ldProofWithoutProofValues)
				.defaultContexts(true)
				.build();
		String normalizedProofOptions = jsonLdObjectProofOptions.normalize("urdna2015");

		// obtain the normalized document

		JsonLDObject jsonLdDocumentWithoutProof = JsonLDObject.builder()
				.base(jsonLdObject)
				.build();
		jsonLdDocumentWithoutProof.setDocumentLoader(jsonLdObject.getDocumentLoader());
		LdProof.removeFromJsonLdObject(jsonLdDocumentWithoutProof);
		String normalizedDocument = jsonLdDocumentWithoutProof.normalize("urdna2015");

		// sign

		byte[] signingInput = new byte[64];
		System.arraycopy(SHAUtil.sha256(normalizedProofOptions), 0, signingInput, 0, 32);
		System.arraycopy(SHAUtil.sha256(normalizedDocument), 0, signingInput, 32, 32);

		LdProof.Builder ldProofBuilder = LdProof.builder()
				.base(ldProofWithoutProofValues)
				.defaultContexts(defaultContexts);

		this.sign(ldProofBuilder, signingInput);

		LdProof ldProof = ldProofBuilder.build();

		// add proof to JSON-LD?

		if (addToJsonLdObject) ldProof.addToJsonLDObject(jsonLdObject);

		// done

		return ldProof;
	}

	public LdProof sign(JsonLDObject jsonLdObject) throws IOException, GeneralSecurityException, JsonLDException {

		return this.sign(jsonLdObject, true, false);
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

	public URI getVerificationMethod() {
		return verificationMethod;
	}

	public void setVerificationMethod(URI verificationMethod) {
		this.verificationMethod = verificationMethod;
	}
}
