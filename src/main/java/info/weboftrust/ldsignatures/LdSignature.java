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

	public static final String JSONLD_TERM_PROOF = "proof";
	public static final String JSONLD_TERM_TYPE = "type";
	public static final String JSONLD_TERM_CREATOR = "creator";
	public static final String JSONLD_TERM_CREATED = "created";
	public static final String JSONLD_TERM_DOMAIN = "domain";
	public static final String JSONLD_TERM_NONCE = "nonce";
	public static final String JSONLD_TERM_PROOFPURPOSE = "proofPurpose";
	public static final String JSONLD_TERM_VERIFICATIONMETHOD = "verificationMethod";
	public static final String JSONLD_TERM_PROOFVALUE = "proofValue";
	public static final String JSONLD_TERM_JWS = "jws";
	public static final String JSONLD_TERM_ASSERTIONMETHOD = "assertionMethod";

	public static final SimpleDateFormat DATE_FORMAT;
	public static final SimpleDateFormat DATE_FORMAT_MILLIS;

	private final LinkedHashMap<String, Object> jsonLdProofObject;

	static {

		DATE_FORMAT = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'Z'");
		DATE_FORMAT.setTimeZone(TimeZone.getTimeZone("UTC"));

		DATE_FORMAT_MILLIS = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSSSSS'Z'");
		DATE_FORMAT_MILLIS.setTimeZone(TimeZone.getTimeZone("UTC"));
	}

	protected LdSignature(LinkedHashMap<String, Object> jsonLdProofObject) {

		this.jsonLdProofObject = jsonLdProofObject;
	}

	public LdSignature() {

		this.jsonLdProofObject = new LinkedHashMap<String, Object> ();
	}

	public static LdSignature fromJsonLdProofObject(LinkedHashMap<String, Object> jsonLdProofObject) {

		return new LdSignature(jsonLdProofObject);
	}

	public LinkedHashMap<String, Object> getJsonLdProofObject() {

		return this.jsonLdProofObject;
	}

	@SuppressWarnings("unchecked")
	public static void addContextToJsonLdObject(LinkedHashMap<String, Object> jsonLdObject) {

		Object context = jsonLdObject.get(JsonLdConsts.CONTEXT);
		ArrayList<Object> contexts;

		// add as single value

		if (context == null) {

			jsonLdObject.put(JsonLdConsts.CONTEXT, JSONLD_CONTEXT_SECURITY_V2);
			return;
		}

		// add as array member

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

	public static void addToJsonLdObject(LinkedHashMap<String, Object> jsonLdObject, LinkedHashMap<String, Object> jsonLdProofObject) {

		Object proof = jsonLdObject.get(JSONLD_TERM_PROOF);

		// add as single value

		if (proof == null) {

			jsonLdObject.put(JSONLD_TERM_PROOF, jsonLdProofObject);
			return;
		}

		// add as array member

		ArrayList<Object> proofs;

		if (proof instanceof ArrayList<?>) {

			proofs = (ArrayList<Object>) proof;
		} else {

			proofs = new ArrayList<Object> ();
			proofs.add(proof);
			jsonLdObject.put(JSONLD_TERM_PROOF, proofs);
		}

		if (! proofs.contains(jsonLdProofObject)) {

			proofs.add(jsonLdProofObject);
		}
	}

	public void addToJsonLdObject(LinkedHashMap<String, Object> jsonLdObject, boolean addContext) {

		if (addContext) addContextToJsonLdObject(jsonLdObject);

		addToJsonLdObject(jsonLdObject, this.getJsonLdProofObject());
	}

	public void addToJsonLdObject(LinkedHashMap<String, Object> jsonLdObject) {

		this.addToJsonLdObject(jsonLdObject, false);
	}

	public static void removeFromJsonLdObject(LinkedHashMap<String, Object> jsonLdObject) {

		jsonLdObject.remove(JSONLD_TERM_PROOF);
	}

	public static void removeLdProofValues(LinkedHashMap<String, Object> jsonLdObject) {

		jsonLdObject.remove(JSONLD_TERM_PROOFVALUE);
		jsonLdObject.remove(JSONLD_TERM_JWS);
	}

	@SuppressWarnings("unchecked")
	public static LdSignature getFromJsonLdObject(LinkedHashMap<String, Object> jsonLdObject) {

		LinkedHashMap<String, Object> jsonLdProofObject = (LinkedHashMap<String, Object>) jsonLdObject.get(JSONLD_TERM_PROOF);
		if (jsonLdProofObject == null) return null;

		return new LdSignature(jsonLdProofObject);
	}

	public String getType() {
		return (String) this.jsonLdProofObject.get(JSONLD_TERM_TYPE);
	}

	public void setType(String type) {
		this.jsonLdProofObject.put(JSONLD_TERM_TYPE, type);
	}

	public URI getCreator() {
		Object object = this.jsonLdProofObject.get(JSONLD_TERM_CREATOR);
		if (object instanceof URI) return (URI) object;
		if (object instanceof String) return URI.create((String) object);
		return null;
	}

	public void setCreator(URI creator) {
		this.jsonLdProofObject.put(JSONLD_TERM_CREATOR, creator);
	}

	public Date getCreated() {
		String createdString = (String) this.jsonLdProofObject.get(JSONLD_TERM_CREATED);
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
		this.jsonLdProofObject.put(JSONLD_TERM_CREATED, DATE_FORMAT.format(created));
	}

	public String getDomain() {
		return (String) this.jsonLdProofObject.get(JSONLD_TERM_DOMAIN);
	}

	public void setDomain(String domain) {
		this.jsonLdProofObject.put(JSONLD_TERM_DOMAIN, domain);
	}

	public String getNonce() {
		return (String) this.jsonLdProofObject.get(JSONLD_TERM_NONCE);
	}

	public void setNonce(String nonce) {
		this.jsonLdProofObject.put(JSONLD_TERM_NONCE, nonce);
	}

	public String getProofPurpose() {
		return (String) this.jsonLdProofObject.get(JSONLD_TERM_PROOFPURPOSE);
	}

	public void setProofPurpose(String proofPurpose) {
		this.jsonLdProofObject.put(JSONLD_TERM_PROOFPURPOSE, proofPurpose);
	}

	public String getVerificationMethod() {
		return (String) this.jsonLdProofObject.get(JSONLD_TERM_VERIFICATIONMETHOD);
	}

	public void setVerificationMethod(String verificationMethod) {
		this.jsonLdProofObject.put(JSONLD_TERM_VERIFICATIONMETHOD, verificationMethod);
	}

	public String getProofValue() {
		return (String) this.jsonLdProofObject.get(JSONLD_TERM_PROOFVALUE);
	}

	public void setProofValue(String proofValue) {
		this.jsonLdProofObject.put(JSONLD_TERM_PROOFVALUE, proofValue);
	}

	public String getJws() {
		return (String) this.jsonLdProofObject.get(JSONLD_TERM_JWS);
	}

	public void setJws(String jws) {
		this.jsonLdProofObject.put(JSONLD_TERM_JWS, jws);
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + ((jsonLdProofObject == null) ? 0 : jsonLdProofObject.hashCode());
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
		if (jsonLdProofObject == null) {
			if (other.jsonLdProofObject != null)
				return false;
		} else if (!jsonLdProofObject.equals(other.jsonLdProofObject))
			return false;
		return true;
	}

	@Override
	public String toString() {
		return "LdSignature [jsonLdProofObject=" + jsonLdProofObject + "]";
	}
}
