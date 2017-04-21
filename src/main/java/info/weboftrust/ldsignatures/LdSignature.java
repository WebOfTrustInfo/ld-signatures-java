package info.weboftrust.ldsignatures;

import java.net.URI;
import java.util.LinkedHashMap;

public class LdSignature {

	public static final URI URI_SIGNATURE = URI.create("https://w3id.org/security#signature");

	public static final URI URI_TYPE = URI.create("http://www.w3.org/1999/02/22-rdf-syntax-ns#type");
	public static final URI URI_CREATOR = URI.create("http://purl.org/dc/terms/creator");
	public static final URI URI_CREATED = URI.create("http://purl.org/dc/terms/created");
	public static final URI URI_DOMAIN = URI.create("https://w3id.org/security#domain");
	public static final URI URI_NONCE = URI.create("https://w3id.org/security#nonoce");
	public static final URI URI_SIGNATUREVALUE= URI.create("https://w3id.org/security#signatureValue");

	public static final String JSONLD_TERM_SIGNATURE = "signature";

	public static final String JSONLD_TERM_TYPE = "type";
	public static final String JSONLD_TERM_CREATOR = "creator";
	public static final String JSONLD_TERM_CREATED = "created";
	public static final String JSONLD_TERM_DOMAIN = "domain";
	public static final String JSONLD_TERM_NONCE = "nonce";
	public static final String JSONLD_TERM_SIGNATUREVALUE = "signatureValue";

	private URI type;
	private URI creator;
	private String created;
	private String domain;
	private String nonce;
	private String signatureValue;

	public LinkedHashMap<String, Object> buildJsonLdSignatureObject() {

		LinkedHashMap<String, Object> jsonLdSignatureObject = new LinkedHashMap<String, Object> ();

		if (this.type != null) jsonLdSignatureObject.put(JSONLD_TERM_TYPE, this.type);
		if (this.creator != null) jsonLdSignatureObject.put(JSONLD_TERM_CREATOR, this.creator);
		if (this.created != null) jsonLdSignatureObject.put(JSONLD_TERM_CREATED, this.created);
		if (this.domain != null) jsonLdSignatureObject.put(JSONLD_TERM_DOMAIN, this.domain);
		if (this.nonce != null) jsonLdSignatureObject.put(JSONLD_TERM_NONCE, this.nonce);
		if (this.signatureValue != null) jsonLdSignatureObject.put(JSONLD_TERM_SIGNATUREVALUE, this.signatureValue);

		return jsonLdSignatureObject;
	}

	public void addToJsonLdObject(LinkedHashMap<String, Object> jsonLdObject) {

		LinkedHashMap<String, Object> jsonLdSignatureObject = this.buildJsonLdSignatureObject();

		jsonLdObject.put(JSONLD_TERM_SIGNATURE, jsonLdSignatureObject);
	}

	public URI getType() {
		return type;
	}

	public void setType(URI type) {
		this.type = type;
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

	public String getSignatureValue() {
		return signatureValue;
	}

	public void setSignatureValue(String signatureValue) {
		this.signatureValue = signatureValue;
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + ((created == null) ? 0 : created.hashCode());
		result = prime * result + ((creator == null) ? 0 : creator.hashCode());
		result = prime * result + ((domain == null) ? 0 : domain.hashCode());
		result = prime * result + ((nonce == null) ? 0 : nonce.hashCode());
		result = prime * result + ((signatureValue == null) ? 0 : signatureValue.hashCode());
		result = prime * result + ((type == null) ? 0 : type.hashCode());
		return result;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj)
			return true;
		if (obj == null)
			return false;
		if (getClass() != obj.getClass())
			return false;
		LdSignature other = (LdSignature) obj;
		if (created == null) {
			if (other.created != null)
				return false;
		} else if (!created.equals(other.created))
			return false;
		if (creator == null) {
			if (other.creator != null)
				return false;
		} else if (!creator.equals(other.creator))
			return false;
		if (domain == null) {
			if (other.domain != null)
				return false;
		} else if (!domain.equals(other.domain))
			return false;
		if (nonce == null) {
			if (other.nonce != null)
				return false;
		} else if (!nonce.equals(other.nonce))
			return false;
		if (signatureValue == null) {
			if (other.signatureValue != null)
				return false;
		} else if (!signatureValue.equals(other.signatureValue))
			return false;
		if (type == null) {
			if (other.type != null)
				return false;
		} else if (!type.equals(other.type))
			return false;
		return true;
	}

	@Override
	public String toString() {
		return "LdSignature [type=" + type + ", creator=" + creator + ", created=" + created + ", domain=" + domain
				+ ", nonce=" + nonce + ", signatureValue=" + signatureValue + "]";
	}
}
