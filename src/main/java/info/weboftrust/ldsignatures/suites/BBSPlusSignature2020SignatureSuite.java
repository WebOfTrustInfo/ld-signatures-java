package info.weboftrust.ldsignatures.suites;

import java.net.URI;

public class BBSPlusSignature2020SignatureSuite extends SignatureSuite {

	BBSPlusSignature2020SignatureSuite() {

		super(
				"Ed25519Signature2020",
				URI.create("https://w3id.org/security#BbsBlsSignature2020"),
				URI.create("https://w3id.org/security#URDNA2015"),
				URI.create("https://www.blake2.net/"),
				URI.create("https://electriccoin.co/blog/new-snark-curve/"));
	}
}
