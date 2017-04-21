package info.weboftrust.ldsignatures.signer;

import java.net.URI;

import info.weboftrust.ldsignatures.suites.SignatureSuite;

public abstract class LdSigner <SIGNATURESUITE extends SignatureSuite> {

	protected URI creator;
	protected String created;
	protected String domain;
	protected String nonce;

	public LdSigner(URI creator, String created, String domain, String nonce) {

		this.creator = creator;
		this.created = created;
		this.domain = domain;
		this.nonce = nonce;
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

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + ((created == null) ? 0 : created.hashCode());
		result = prime * result + ((creator == null) ? 0 : creator.hashCode());
		result = prime * result + ((domain == null) ? 0 : domain.hashCode());
		result = prime * result + ((nonce == null) ? 0 : nonce.hashCode());
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
		LdSigner other = (LdSigner) obj;
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
		return true;
	}

	@Override
	public String toString() {
		return "LdSigner [creator=" + creator + ", created=" + created + ", domain=" + domain + ", nonce=" + nonce
				+ "]";
	}
}
