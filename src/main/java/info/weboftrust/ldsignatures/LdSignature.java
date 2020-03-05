package info.weboftrust.ldsignatures;

import java.net.URI;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.TimeZone;

import com.github.jsonldjava.core.JsonLdConsts;

public class LdSignature {

	public static final String JSONLD_CONTEXT_SECURITY_V1 = "https://w3id.org/security/v1";
	public static final String JSONLD_CONTEXT_SECURITY_V2 = "https://w3id.org/security/v2";

	public static final URI URI_SIGNATURE = URI.create("https://w3id.org/security#signature");

	public static final URI URI_TYPE = URI.create("http://www.w3.org/1999/02/22-rdf-syntax-ns#type");
	public static final URI URI_CREATOR = URI.create("http://purl.org/dc/terms/creator");
	public static final URI URI_CREATED = URI.create("http://purl.org/dc/terms/created");
	public static final URI URI_DOMAIN = URI.create("https://w3id.org/security#domain");
	public static final URI URI_NONCE = URI.create("https://w3id.org/security#nonce");
	public static final URI URI_SIGNATUREVALUE = URI.create("https://w3id.org/security#signatureValue");

	public static final String JSONLD_TERM_PROOF = "proof";

	public static final String JSONLD_TERM_TYPE = "type";
	public static final String JSONLD_TERM_CREATOR = "creator";
	public static final String JSONLD_TERM_CREATED = "created";
	public static final String JSONLD_TERM_DOMAIN = "domain";
	public static final String JSONLD_TERM_NONCE = "nonce";
	public static final String JSONLD_TERM_PROOFPURPOSE = "proofPurpose";
	public static final String JSONLD_TERM_VERIFICATIONMETHOD = "verificationMethod";
	public static final String JSONLD_TERM_SIGNATUREVALUE = "signatureValue";
	public static final String JSONLD_TERM_JWS = "jws";

	public static final String JSONLD_TERM_ASSERTIONMETHOD = "assertionMethod";

	public static final SimpleDateFormat DATE_FORMAT;
	public static final SimpleDateFormat DATE_FORMAT_MILLIS;

	private final LinkedHashMap<String, Object> jsonLdSignatureObject;

	static {

		DATE_FORMAT = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'Z'");
		DATE_FORMAT.setTimeZone(TimeZone.getTimeZone("UTC"));

		DATE_FORMAT_MILLIS = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSSSSS'Z'");
		DATE_FORMAT_MILLIS.setTimeZone(TimeZone.getTimeZone("UTC"));
	}

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

	@SuppressWarnings("unchecked")
	public static void addSecurityContextToJsonLdObject(LinkedHashMap<String, Object> jsonLdObject) {

		Object context = jsonLdObject.get(JsonLdConsts.CONTEXT);
		ArrayList<Object> contexts;

		if (context instanceof ArrayList<?>) {

			contexts = (ArrayList<Object>) context;
		} else {

			contexts = new ArrayList<Object> ();
			contexts.add(context);
			jsonLdObject.put(JsonLdConsts.CONTEXT, contexts);
		}

		if (! contexts.contains(JSONLD_CONTEXT_SECURITY_V2)) {

			contexts.add(JSONLD_CONTEXT_SECURITY_V2);
		}
	}

	public static void addToJsonLdObject(LinkedHashMap<String, Object> jsonLdObject, LinkedHashMap<String, Object> jsonLdSignatureObject, boolean addSecurityContext) {

		if (addSecurityContext) addSecurityContextToJsonLdObject(jsonLdObject);

		jsonLdObject.put(JSONLD_TERM_PROOF, jsonLdSignatureObject);
	}

	public static void addToJsonLdObject(LinkedHashMap<String, Object> jsonLdObject, LinkedHashMap<String, Object> jsonLdSignatureObject) {

		addToJsonLdObject(jsonLdObject, jsonLdSignatureObject, false);
	}

	public void addToJsonLdObject(LinkedHashMap<String, Object> jsonLdObject, boolean addSecurityContext) {

		addToJsonLdObject(jsonLdObject, this.getJsonLdSignatureObject(), addSecurityContext);
	}

	public void addToJsonLdObject(LinkedHashMap<String, Object> jsonLdObject) {

		addToJsonLdObject(jsonLdObject, this.getJsonLdSignatureObject());
	}

	public static void removeFromJsonLdObject(LinkedHashMap<String, Object> jsonLdObject) {

		jsonLdObject.remove(JSONLD_TERM_PROOF);
	}

	public static void removeLdSignatureValues(LinkedHashMap<String, Object> jsonLdObject) {

		jsonLdObject.remove(JSONLD_TERM_SIGNATUREVALUE);
		jsonLdObject.remove(JSONLD_TERM_JWS);
	}

	@SuppressWarnings("unchecked")
	public static LdSignature getFromJsonLdObject(LinkedHashMap<String, Object> jsonLdObject) {

		LinkedHashMap<String, Object> jsonLdSignatureObject = (LinkedHashMap<String, Object>) jsonLdObject.get(JSONLD_TERM_PROOF);
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
		Object object = this.jsonLdSignatureObject.get(JSONLD_TERM_CREATOR);
		if (object instanceof URI) return (URI) object;
		if (object instanceof String) return URI.create((String) object);
		return null;
	}

	public void setCreator(URI creator) {
		this.jsonLdSignatureObject.put(JSONLD_TERM_CREATOR, creator);
	}

	public Date getCreated() {
		String createdString = (String) this.jsonLdSignatureObject.get(JSONLD_TERM_CREATED);
		if (createdString == null) return null;
		try {
			return DATE_FORMAT.parse(createdString);
		} catch (ParseException ex) {
			try {
				return DATE_FORMAT_MILLIS.parse(createdString);
			} catch (ParseException ex2) {
				throw new RuntimeException(ex.getMessage(), ex);
			}
		}
	}

	public void setCreated(Date created) {
		this.jsonLdSignatureObject.put(JSONLD_TERM_CREATED, DATE_FORMAT.format(created));
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

	public String getProofPurpose() {
		return (String) this.jsonLdSignatureObject.get(JSONLD_TERM_PROOFPURPOSE);
	}

	public void setProofPurpose(String proofPurpose) {
		this.jsonLdSignatureObject.put(JSONLD_TERM_PROOFPURPOSE, proofPurpose);
	}

	public String getVerificationMethod() {
		return (String) this.jsonLdSignatureObject.get(JSONLD_TERM_VERIFICATIONMETHOD);
	}

	public void setVerificationMethod(String verificationMethod) {
		this.jsonLdSignatureObject.put(JSONLD_TERM_VERIFICATIONMETHOD, verificationMethod);
	}

	public String getSignatureValue() {
		return (String) this.jsonLdSignatureObject.get(JSONLD_TERM_SIGNATUREVALUE);
	}

	public void setSignatureValue(String signatureValue) {
		this.jsonLdSignatureObject.put(JSONLD_TERM_SIGNATUREVALUE, signatureValue);
	}

	public String getJws() {
		return (String) this.jsonLdSignatureObject.get(JSONLD_TERM_JWS);
	}

	public void setJws(String jws) {
		this.jsonLdSignatureObject.put(JSONLD_TERM_JWS, jws);
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
