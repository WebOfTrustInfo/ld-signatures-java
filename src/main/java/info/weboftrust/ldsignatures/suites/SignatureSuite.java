package info.weboftrust.ldsignatures.suites;

import java.net.URI;

public abstract class SignatureSuite {

	public static final URI URI_TYPE_SIGNATURESUITE = URI.create("https://w3id.org/security#SignatureSuite");

	private URI id;
	private URI type;
	private URI canonicalizationAlgorithm;
	private URI digestAlgorithm;
	private URI signatureAlgorithm;

	public SignatureSuite(URI id, URI canonicalizationAlgorithm, URI digestAlgorithm, URI signatureAlgorithm) {

		this.id = id;
		this.type = URI_TYPE_SIGNATURESUITE;
		this.canonicalizationAlgorithm = canonicalizationAlgorithm;
		this.digestAlgorithm = digestAlgorithm;
		this.signatureAlgorithm = signatureAlgorithm;
	}

	public URI getId() {
		return id;
	}

	public URI getType() {
		return type;
	}

	public URI getCanonicalizationAlgorithm() {
		return canonicalizationAlgorithm;
	}

	public URI getDigestAlgorithm() {
		return digestAlgorithm;
	}

	public URI getSignatureAlgorithm() {
		return signatureAlgorithm;
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + ((canonicalizationAlgorithm == null) ? 0 : canonicalizationAlgorithm.hashCode());
		result = prime * result + ((digestAlgorithm == null) ? 0 : digestAlgorithm.hashCode());
		result = prime * result + ((id == null) ? 0 : id.hashCode());
		result = prime * result + ((signatureAlgorithm == null) ? 0 : signatureAlgorithm.hashCode());
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
		SignatureSuite other = (SignatureSuite) obj;
		if (canonicalizationAlgorithm == null) {
			if (other.canonicalizationAlgorithm != null)
				return false;
		} else if (!canonicalizationAlgorithm.equals(other.canonicalizationAlgorithm))
			return false;
		if (digestAlgorithm == null) {
			if (other.digestAlgorithm != null)
				return false;
		} else if (!digestAlgorithm.equals(other.digestAlgorithm))
			return false;
		if (id == null) {
			if (other.id != null)
				return false;
		} else if (!id.equals(other.id))
			return false;
		if (signatureAlgorithm == null) {
			if (other.signatureAlgorithm != null)
				return false;
		} else if (!signatureAlgorithm.equals(other.signatureAlgorithm))
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
		return "SignatureSuite [id=" + id + ", type=" + type + ", canonicalizationAlgorithm="
				+ canonicalizationAlgorithm + ", digestAlgorithm=" + digestAlgorithm + ", signatureAlgorithm="
				+ signatureAlgorithm + "]";
	}
}
