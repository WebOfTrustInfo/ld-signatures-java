package info.weboftrust.ldsignatures.signer;

import java.net.URI;
import java.text.ParseException;
import java.util.LinkedHashMap;

import org.jose4j.lang.JoseException;

import com.github.jsonldjava.core.JsonLdError;

import info.weboftrust.ldsignatures.LdSignature;
import info.weboftrust.ldsignatures.suites.SignatureSuite;
import info.weboftrust.ldsignatures.util.CanonicalizationUtil;

public abstract class LdSigner <SIGNATURESUITE extends SignatureSuite> {

	protected SIGNATURESUITE signatureSuite;
	protected URI creator;
	protected String created;
	protected String domain;
	protected String nonce;

	protected LdSigner(SIGNATURESUITE signatureSuite, URI creator, String created, String domain, String nonce) {

		this.signatureSuite = signatureSuite;
		this.creator = creator;
		this.created = created;
		this.domain = domain;
		this.nonce = nonce;
	}

	public abstract String sign(String canonicalizedDocument) throws JoseException;

	public LdSignature sign(LinkedHashMap<String, Object> jsonLdObject, boolean add) throws JsonLdError, JoseException {

		// obtain the canonicalized document

		LinkedHashMap<String, Object> jsonLdObjectWithoutSignature = new LinkedHashMap<String, Object> (jsonLdObject);
		LdSignature.removeFromJsonLdObject(jsonLdObjectWithoutSignature);
		String canonicalizedDocument = CanonicalizationUtil.buildCanonicalizedDocument(jsonLdObjectWithoutSignature);

		// sign

		String signatureValue = this.sign(canonicalizedDocument);

		// build the signature object

		LdSignature ldSignature = new LdSignature();

		ldSignature.setType(this.signatureSuite.getId());
		ldSignature.setCreator(this.creator);
		ldSignature.setCreated(this.created);
		ldSignature.setDomain(this.domain);
		ldSignature.setNonce(this.nonce);
		ldSignature.setSignatureValue(signatureValue);

		// add signature to JSON-LD?

		if (add) ldSignature.addToJsonLdObject(jsonLdObject);

		// done

		return ldSignature;
	}

	public LdSignature sign(LinkedHashMap<String, Object> jsonLdObject) throws JsonLdError, ParseException, JoseException {

		return sign(jsonLdObject, true);
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
