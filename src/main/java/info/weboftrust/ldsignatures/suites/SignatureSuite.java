package info.weboftrust.ldsignatures.suites;

import com.danubetech.keyformats.jose.KeyTypeName;

import java.net.URI;
import java.util.List;
import java.util.Map;
import java.util.Objects;

public abstract class SignatureSuite {

	public static final URI URI_TYPE_SIGNATURESUITE = URI.create("https://w3id.org/security#SignatureSuite");

	private final String term;
	private final URI id;
	private final URI type;
	private final URI canonicalizationAlgorithm;
	private final URI digestAlgorithm;
	private final URI proofAlgorithm;
	private final List<KeyTypeName> keyTypeNames;
	private final Map<KeyTypeName, List<String>> jwsAlgorithmForKeyTypeName;
	private final List<URI> supportedJsonLDContexts;

	public SignatureSuite(String term, URI id, URI canonicalizationAlgorithm, URI digestAlgorithm, URI proofAlgorithm, List<KeyTypeName> keyTypeNames, Map<KeyTypeName, List<String>> jwsAlgorithmForKeyTypeName,List<URI> supportedJsonLDContexts) {
		this.term = term;
		this.id = id;
		this.type = URI_TYPE_SIGNATURESUITE;
		this.canonicalizationAlgorithm = canonicalizationAlgorithm;
		this.digestAlgorithm = digestAlgorithm;
		this.proofAlgorithm = proofAlgorithm;
		this.keyTypeNames = keyTypeNames;
		this.jwsAlgorithmForKeyTypeName = jwsAlgorithmForKeyTypeName;
		this.supportedJsonLDContexts = supportedJsonLDContexts;
	}

	public List<String> findJwsAlgorithmsForKeyTypeName(KeyTypeName keyTypeName) {
		return this.getJwsAlgorithmsForKeyTypeName().get(keyTypeName);
	}

	public String findDefaultJwsAlgorithmForKeyTypeName(KeyTypeName keyTypeName) {
		List<String> foundAlgorithmsForKeyTypeName = this.findJwsAlgorithmsForKeyTypeName(keyTypeName);
		return (foundAlgorithmsForKeyTypeName == null || foundAlgorithmsForKeyTypeName.isEmpty()) ? null : foundAlgorithmsForKeyTypeName.get(0);
	}

	public URI getDefaultSupportedJsonLDContext() {
		List<URI> supportedJsonLDContexts = this.getSupportedJsonLDContexts();
		return (supportedJsonLDContexts == null || supportedJsonLDContexts.isEmpty()) ? null : supportedJsonLDContexts.get(0);
	}

	public String getTerm() {
		return term;
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

	public URI getProofAlgorithm() {
		return proofAlgorithm;
	}

	public List<KeyTypeName> getKeyTypeNames() {
		return keyTypeNames;
	}

	public Map<KeyTypeName, List<String>> getJwsAlgorithmsForKeyTypeName() {
		return jwsAlgorithmForKeyTypeName;
	}

	public List<URI> getSupportedJsonLDContexts() {
		return supportedJsonLDContexts;
	}

	@Override
	public boolean equals(Object o) {
		if (this == o) return true;
		if (o == null || getClass() != o.getClass()) return false;
		SignatureSuite that = (SignatureSuite) o;
		return Objects.equals(term, that.term) && Objects.equals(id, that.id) && Objects.equals(type, that.type) && Objects.equals(canonicalizationAlgorithm, that.canonicalizationAlgorithm) && Objects.equals(digestAlgorithm, that.digestAlgorithm) && Objects.equals(proofAlgorithm, that.proofAlgorithm) && Objects.equals(keyTypeNames, that.keyTypeNames) && Objects.equals(jwsAlgorithmForKeyTypeName, that.jwsAlgorithmForKeyTypeName) && Objects.equals(supportedJsonLDContexts, that.supportedJsonLDContexts);
	}

	@Override
	public int hashCode() {
		return Objects.hash(term, id, type, canonicalizationAlgorithm, digestAlgorithm, proofAlgorithm, keyTypeNames, jwsAlgorithmForKeyTypeName, supportedJsonLDContexts);
	}

	@Override
	public String toString() {
		return "SignatureSuite{" +
				"term='" + term + '\'' +
				", id=" + id +
				", type=" + type +
				", canonicalizationAlgorithm=" + canonicalizationAlgorithm +
				", digestAlgorithm=" + digestAlgorithm +
				", proofAlgorithm=" + proofAlgorithm +
				", keyTypeNames=" + keyTypeNames +
				", jwsAlgorithmForKeyTypeName=" + jwsAlgorithmForKeyTypeName +
				", supportedJsonLDContexts=" + supportedJsonLDContexts +
				'}';
	}
}
