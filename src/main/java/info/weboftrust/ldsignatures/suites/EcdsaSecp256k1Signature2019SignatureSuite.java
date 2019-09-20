package info.weboftrust.ldsignatures.suites;

import java.net.URI;

public class EcdsaSecp256k1Signature2019SignatureSuite extends SignatureSuite {

	EcdsaSecp256k1Signature2019SignatureSuite() {

		super(
				"EcdsaSecp256k1Signature2019",
				URI.create("https://w3id.org/security#EcdsaSecp256k1Signature2019"),
				URI.create("https://w3id.org/security#URDNA2015"),
				URI.create("http://w3id.org/digests#sha256"),
				URI.create("http://w3id.org/security#secp256k1"));
	}
}
