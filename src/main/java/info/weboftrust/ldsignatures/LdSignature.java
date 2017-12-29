package info.weboftrust.ldsignatures;

import java.net.URI;
import java.util.LinkedHashMap;

public class LdSignature {

	public static final URI URI_SIGNATURE = URI.create("https://w3id.org/security#signature");

	public static final URI URI_TYPE = URI.create("http://www.w3.org/1999/02/22-rdf-syntax-ns#type");
	public static final URI URI_CREATOR = URI.create("http://purl.org/dc/terms/creator");
	public static final URI URI_CREATED = URI.create("http://purl.org/dc/terms/created");
	public static final URI URI_DOMAIN = URI.create("https://w3id.org/security#domain");
	public static final URI URI_NONCE = URI.create("https://w3id.org/security#nonce");
	public static final URI URI_SIGNATUREVALUE = URI.create("https://w3id.org/security#signatureValue");

	public static final String JSONLD_TERM_SIGNATURE = "signature";

	public static final String JSONLD_TERM_TYPE = "type";
	public static final String JSONLD_TERM_CREATOR = "creator";
	public static final String JSONLD_TERM_CREATED = "created";
	public static final String JSONLD_TERM_DOMAIN = "domain";
	public static final String JSONLD_TERM_NONCE = "nonce";
	public static final String JSONLD_TERM_SIGNATUREVALUE = "signatureValue";

	private final LinkedHashMap<String, Object> jsonLdSignatureObject;

	private LdSignature(LinkedHashMap<String, Object> jsonLdSignatureObject) { 

		this.jsonLdSignatureObject = jsonLdSignatureObject;
	}

	public LdSignature() {

		this.jsonLdSignatureObject = new LinkedHashMap<String, Object> ();
	}

	public static LdSignature fromJsonLdSignatureObject(LinkedHashMap<String, Object> jsonLdSignatureObject) {

		return new LdSignature(jsonLdSignatureObject);
	}

	public LinkedHashMap<String, Object> getJsonLdSignatureObject() {

		return this.jsonLdSignatureObject;
	}

	public static void addToJsonLdObject(LinkedHashMap<String, Object> jsonLdObject, LinkedHashMap<String, Object> jsonLdSignatureObject) {

		jsonLdObject.put(JSONLD_TERM_SIGNATURE, jsonLdSignatureObject);
	}

	public void addToJsonLdObject(LinkedHashMap<String, Object> jsonLdObject) {

		addToJsonLdObject(jsonLdObject, this.getJsonLdSignatureObject());
	}

	public static void removeFromJsonLdObject(LinkedHashMap<String, Object> jsonLdObject) {

		jsonLdObject.remove(JSONLD_TERM_SIGNATURE);
	}

	@SuppressWarnings("unchecked")
	public static LdSignature getFromJsonLdObject(LinkedHashMap<String, Object> jsonLdObject) {

		LinkedHashMap<String, Object> jsonLdSignatureObject = (LinkedHashMap<String, Object>) jsonLdObject.get(JSONLD_TERM_SIGNATURE);
		if (jsonLdSignatureObject == null) return null;

		return new LdSignature(jsonLdSignatureObject);
	}

	public String getType() {
		return (String) this.jsonLdSignatureObject.get(JSONLD_TERM_TYPE);
	}

	public void setType(String type) {
		this.jsonLdSignatureObject.put(JSONLD_TERM_TYPE, type);
	}

	public URI getCreator() {
		return (URI) this.jsonLdSignatureObject.get(JSONLD_TERM_CREATOR);
	}

	public void setCreator(URI creator) {
		this.jsonLdSignatureObject.put(JSONLD_TERM_CREATOR, creator);
	}

	public String getCreated() {
		return (String) this.jsonLdSignatureObject.get(JSONLD_TERM_CREATED);
	}

	public void setCreated(String created) {
		this.jsonLdSignatureObject.put(JSONLD_TERM_CREATED, created);
	}

	public String getDomain() {
		return (String) this.jsonLdSignatureObject.get(JSONLD_TERM_DOMAIN);
	}

	public void setDomain(String domain) {
		this.jsonLdSignatureObject.put(JSONLD_TERM_DOMAIN, domain);
	}

	public String getNonce() {
		return (String) this.jsonLdSignatureObject.get(JSONLD_TERM_NONCE);
	}

	public void setNonce(String nonce) {
		this.jsonLdSignatureObject.put(JSONLD_TERM_NONCE, nonce);
	}

	public String getSignatureValue() {
		return (String) this.jsonLdSignatureObject.get(JSONLD_TERM_SIGNATUREVALUE);
	}

	public void setSignatureValue(String signatureValue) {
		this.jsonLdSignatureObject.put(JSONLD_TERM_SIGNATUREVALUE, signatureValue);
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + ((jsonLdSignatureObject == null) ? 0 : jsonLdSignatureObject.hashCode());
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
		if (jsonLdSignatureObject == null) {
			if (other.jsonLdSignatureObject != null)
				return false;
		} else if (!jsonLdSignatureObject.equals(other.jsonLdSignatureObject))
			return false;
		return true;
	}

	@Override
	public String toString() {
		return "LdSignature [jsonLdSignatureObject=" + jsonLdSignatureObject + "]";
	}
}
