package info.weboftrust.ldsignatures.suites;

import java.net.URI;

public class EcdsaKoblitzSignature2016SignatureSuite extends SignatureSuite {

	EcdsaKoblitzSignature2016SignatureSuite() {

		super(
				"EcdsaKoblitzSignature2016",
				URI.create("https://w3id.org/security#EcdsaKoblitzSignature2016"),
				URI.create("https://w3id.org/security#URDNA2015"),
				URI.create("http://w3id.org/digests#sha256"),
				URI.create("http://w3id.org/security#koblitz"));
	}
}
