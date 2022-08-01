package info.weboftrust.ldsignatures.suites;

import com.danubetech.keyformats.jose.JWSAlgorithm;
import com.danubetech.keyformats.jose.KeyTypeName;
import info.weboftrust.ldsignatures.jsonld.LDSecurityContexts;

import java.net.URI;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

public class RsaSignature2018SignatureSuite extends SignatureSuite {

	RsaSignature2018SignatureSuite() {

		super(
				"RsaSignature2018",
				URI.create("https://w3id.org/security#RsaSignature2018"),
				URI.create("https://w3id.org/security#GCA2015"),
				URI.create("https://registry.ietf.org/ietf-digest-algorithms#SHA256"),
				URI.create("https://registry.ietf.org/ietf-jose-jws-algorithms#RS256"),
				List.of(KeyTypeName.RSA),
				Map.of(KeyTypeName.RSA, List.of(JWSAlgorithm.RS256)),
				Arrays.asList(URI.create("https://www.w3.org/2018/credentials/v1"), LDSecurityContexts.JSONLD_CONTEXT_W3ID_SECURITY_V3));

	}
}
