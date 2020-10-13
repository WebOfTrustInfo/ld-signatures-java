package info.weboftrust.ldsignatures;

import java.io.Reader;
import java.io.StringReader;
import java.net.URI;
import java.util.*;

import foundation.identity.jsonld.JsonLDObject;
import foundation.identity.jsonld.JsonLDUtils;
import info.weboftrust.ldsignatures.jsonld.LDSecurityContexts;
import info.weboftrust.ldsignatures.jsonld.LDSecurityKeywords;

import javax.json.Json;
import javax.json.JsonObject;

public class LdProof extends JsonLDObject {

	public static final URI[] DEFAULT_JSONLD_CONTEXTS = { LDSecurityContexts.JSONLD_CONTEXT_W3ID_SECURITY_V2 };
	public static final String[] DEFAULT_JSONLD_TYPES = { };
	public static final String DEFAULT_JSONLD_PREDICATE = LDSecurityKeywords.JSONLD_TERM_PROOF;

	private LdProof() {
		super(LDSecurityContexts.DOCUMENT_LOADER);
	}

	public LdProof(JsonObject jsonObject) {
		super(LDSecurityContexts.DOCUMENT_LOADER, jsonObject);
	}

	/*
	 * Factory methods
	 */

	public static class Builder extends JsonLDObject.Builder<Builder, LdProof> {

		private URI creator;
		private Date created;
		private String domain;
		private String nonce;
		private String proofPurpose;
		private String verificationMethod;
		private String proofValue;
		private String jws;

		public Builder(LdProof jsonLDObject) {
			super(jsonLDObject);
		}

		@Override
		public LdProof build() {

			super.build();

			// add JSON-LD properties
			if (this.creator != null) JsonLDUtils.jsonLdAddString(this.jsonLDObject, LDSecurityKeywords.JSONLD_TERM_CREATOR, JsonLDUtils.uriToString(this.creator));
			if (this.created != null) JsonLDUtils.jsonLdAddString(this.jsonLDObject, LDSecurityKeywords.JSONLD_TERM_CREATED, JsonLDUtils.dateToString(this.created));
			if (this.domain != null) JsonLDUtils.jsonLdAddString(this.jsonLDObject, LDSecurityKeywords.JSONLD_TERM_DOMAIN, this.domain);
			if (this.nonce != null) JsonLDUtils.jsonLdAddString(this.jsonLDObject, LDSecurityKeywords.JSONLD_TERM_NONCE, this.nonce);
			if (this.proofPurpose != null) JsonLDUtils.jsonLdAddString(this.jsonLDObject, LDSecurityKeywords.JSONLD_TERM_PROOFPURPOSE, this.proofPurpose);
			if (this.verificationMethod != null) JsonLDUtils.jsonLdAddString(this.jsonLDObject, LDSecurityKeywords.JSONLD_TERM_VERIFICATIONMETHOD, this.verificationMethod);
			if (this.proofValue != null) JsonLDUtils.jsonLdAddString(this.jsonLDObject, LDSecurityKeywords.JSONLD_TERM_PROOFVALUE, this.proofValue);
			if (this.jws != null) JsonLDUtils.jsonLdAddString(this.jsonLDObject, LDSecurityKeywords.JSONLD_TERM_JWS, this.jws);

			return this.jsonLDObject;
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
		return new Builder(new LdProof());
	}

	/*
	 * Reading the JSON-LD object
	 */

	public static LdProof fromJson(Reader reader) {
		return JsonLDObject.fromJson(LdProof.class, reader);
	}

	public static LdProof fromJson(String json) {
		return JsonLDObject.fromJson(LdProof.class, json);
	}

	/*
	 * Adding, getting, and removing the JSON-LD object
	 */

	public static LdProof getFromJsonLDObject(JsonLDObject jsonLdObject) {
		return JsonLDObject.getFromJsonLDObject(LdProof.class, jsonLdObject);
	}

	public static void removeFromJsonLdObject(JsonLDObject jsonLdObject) {
		JsonLDObject.removeFromJsonLdObject(LdProof.class, jsonLdObject);
	}

	/*
	 * Helper methods
	 */

	public static void removeLdProofValues(JsonLDObject jsonLdObject) {
		JsonLDUtils.jsonLdRemove(jsonLdObject, LDSecurityKeywords.JSONLD_TERM_PROOFVALUE);
		JsonLDUtils.jsonLdRemove(jsonLdObject, LDSecurityKeywords.JSONLD_TERM_JWS);
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
