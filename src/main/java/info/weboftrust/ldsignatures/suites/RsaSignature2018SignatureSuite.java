package info.weboftrust.ldsignatures.suites;

import java.net.URI;

public class RsaSignature2018SignatureSuite extends SignatureSuite {

	RsaSignature2018SignatureSuite() {

		super(
				"RsaSignature2018",
				URI.create("https://w3id.org/security#RsaSignature2018"), 
				URI.create("https://w3id.org/security#GCA2015"), 
				URI.create("https://registry.ietf.org/ietf-digest-algorithms#SHA256"), 
				URI.create("https://registry.ietf.org/ietf-jose-jws-algorithms#RS256"));
	}
}
