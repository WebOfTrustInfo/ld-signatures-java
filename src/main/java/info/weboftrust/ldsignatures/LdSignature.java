package info.weboftrust.ldsignatures;

import java.net.URI;
import java.util.*;

import info.weboftrust.ldsignatures.jsonld.JsonLDObject;
import info.weboftrust.ldsignatures.jsonld.JsonLDUtils;
import info.weboftrust.ldsignatures.jsonld.LDSecurityKeywords;

import javax.json.JsonObject;

public class LdSignature extends JsonLDObject {

	public static final List<String> DEFAULT_CONTEXTS = Collections.singletonList("https://w3id.org/security/v2");

	private LdSignature() {
		super();
	}

	public LdSignature(JsonObject jsonObject) {
		super(jsonObject);
	}

	/*
	 * Factory methods
	 */

	public static class Builder extends JsonLDObject.Builder<Builder, LdSignature> {

		private URI creator;
		private Date created;
		private String domain;
		private String nonce;
		private String proofPurpose;
		private String verificationMethod;
		private String proofValue;
		private String jws;

		public Builder() {
			super(new LdSignature());
		}

		public LdSignature build() {

			LdSignature ldSignature = new LdSignature();

			// add JSON-LD properties
			if (this.creator != null) JsonLDUtils.jsonLdAddString(ldSignature.getJsonObjectBuilder(), LDSecurityKeywords.JSONLD_TERM_CREATOR, JsonLDUtils.uriToString(this.creator));
			if (this.created != null) JsonLDUtils.jsonLdAddString(ldSignature.getJsonObjectBuilder(), LDSecurityKeywords.JSONLD_TERM_CREATED, JsonLDUtils.dateToString(this.created));
			if (this.domain != null) JsonLDUtils.jsonLdAddString(ldSignature.getJsonObjectBuilder(), LDSecurityKeywords.JSONLD_TERM_DOMAIN, this.domain);
			if (this.nonce != null) JsonLDUtils.jsonLdAddString(ldSignature.getJsonObjectBuilder(), LDSecurityKeywords.JSONLD_TERM_NONCE, this.nonce);
			if (this.proofPurpose != null) JsonLDUtils.jsonLdAddString(ldSignature.getJsonObjectBuilder(), LDSecurityKeywords.JSONLD_TERM_PROOFPURPOSE, this.proofPurpose);
			if (this.verificationMethod != null) JsonLDUtils.jsonLdAddString(ldSignature.getJsonObjectBuilder(), LDSecurityKeywords.JSONLD_TERM_VERIFICATIONMETHOD, this.verificationMethod);
			if (this.proofValue != null) JsonLDUtils.jsonLdAddString(ldSignature.getJsonObjectBuilder(), LDSecurityKeywords.JSONLD_TERM_PROOFVALUE, this.proofValue);
			if (this.jws != null) JsonLDUtils.jsonLdAddString(ldSignature.getJsonObjectBuilder(), LDSecurityKeywords.JSONLD_TERM_JWS, this.jws);

			return ldSignature;
		}

		public Builder creator(URI creator) {
			this.creator = creator;
			return this;
		}

		public Builder created(Date created) {
			this.created = created;
			return this;
		}

		public Builder domain(String domain) {
			this.domain = domain;
			return this;
		}

		public Builder nonce(String nonce) {
			this.nonce = nonce;
			return this;
		}

		public Builder proofPurpose(String proofPurpose) {
			this.proofPurpose = proofPurpose;
			return this;
		}

		public Builder verificationMethod(String verificationMethod) {
			this.verificationMethod = verificationMethod;
			return this;
		}

		public Builder proofValue(String proofValue) {
			this.proofValue = proofValue;
			return this;
		}

		public Builder jws(String jws) {
			this.jws = jws;
			return this;
		}
	}

	public static Builder builder() {

		return new Builder();
	}

	/*
	 * Helper methods
	 */

	public static void removeFromJsonLdObject(JsonLDObject jsonLdObject) {

		JsonLDUtils.jsonLdRemove(jsonLdObject.getJsonObjectBuilder(), LDSecurityKeywords.JSONLD_TERM_PROOF);
	}

	public static void removeLdProofValues(JsonLDObject jsonLdObject) {

		JsonLDUtils.jsonLdRemove(jsonLdObject.getJsonObjectBuilder(), LDSecurityKeywords.JSONLD_TERM_PROOFVALUE);
		JsonLDUtils.jsonLdRemove(jsonLdObject.getJsonObjectBuilder(), LDSecurityKeywords.JSONLD_TERM_JWS);
	}

	public static LdSignature getFromJsonLdObject(JsonLDObject jsonLdObject) {

		JsonObject jsonObject = JsonLDUtils.jsonLdGetJsonObject(jsonLdObject.getJsonObject(), LDSecurityKeywords.JSONLD_TERM_PROOF);
		return jsonObject == null ? null : new LdSignature(jsonObject);
	}

	public void addToJsonLdObject(JsonLDObject jsonLdObject) {

		JsonLDUtils.jsonLdAddJsonValue(jsonLdObject.getJsonObjectBuilder(), LDSecurityKeywords.JSONLD_TERM_JWS, jsonLdObject.getJsonObject());
	}

	/*
	 * Getters
	 */

	public URI getCreator() {
		return JsonLDUtils.stringToUri(JsonLDUtils.jsonLdGetString(this.getJsonObject(), LDSecurityKeywords.JSONLD_TERM_CREATOR));
	}

	public Date getCreated() {
		return JsonLDUtils.stringToDate(JsonLDUtils.jsonLdGetString(this.getJsonObject(), LDSecurityKeywords.JSONLD_TERM_CREATED));
	}

	public String getDomain() {
		return JsonLDUtils.jsonLdGetString(this.getJsonObject(), LDSecurityKeywords.JSONLD_TERM_DOMAIN);
	}

	public String getNonce() {
		return JsonLDUtils.jsonLdGetString(this.getJsonObject(), LDSecurityKeywords.JSONLD_TERM_NONCE);
	}

	public String getProofPurpose() {
		return JsonLDUtils.jsonLdGetString(this.getJsonObject(), LDSecurityKeywords.JSONLD_TERM_PROOFPURPOSE);
	}

	public String getVerificationMethod() {
		return JsonLDUtils.jsonLdGetString(this.getJsonObject(), LDSecurityKeywords.JSONLD_TERM_VERIFICATIONMETHOD);
	}

	public String getProofValue() {
		return JsonLDUtils.jsonLdGetString(this.getJsonObject(), LDSecurityKeywords.JSONLD_TERM_PROOFVALUE);
	}

	public String getJws() {
		return JsonLDUtils.jsonLdGetString(this.getJsonObject(), LDSecurityKeywords.JSONLD_TERM_JWS);
	}
}
