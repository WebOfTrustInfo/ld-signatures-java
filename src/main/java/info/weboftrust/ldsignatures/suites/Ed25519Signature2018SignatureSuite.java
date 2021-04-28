package info.weboftrust.ldsignatures.suites;

import java.net.URI;

public class Ed25519Signature2018SignatureSuite extends SignatureSuite {

	Ed25519Signature2018SignatureSuite() {

		super(
				"Ed25519Signature2018",
				URI.create("https://w3id.org/security#Ed25519Signature2018"),
				URI.create("https://w3id.org/security#URDNA2015"),
				URI.create("https://registry.ietf.org/ietf-digest-algorithms#SHA512"),
				URI.create("http://w3id.org/security#ed25519"));
	}
}
