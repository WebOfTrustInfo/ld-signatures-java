package info.weboftrust.ldsignatures.suites;

import com.danubetech.keyformats.jose.JWSAlgorithm;
import com.danubetech.keyformats.jose.KeyTypeName;

import java.net.URI;
import java.util.List;
import java.util.Map;

public class BBSPlusSignature2020SignatureSuite extends SignatureSuite {

	BBSPlusSignature2020SignatureSuite() {

		super(
				"BbsBlsSignature2020",
				URI.create("https://w3id.org/security#BbsBlsSignature2020"),
				URI.create("https://w3id.org/security#URDNA2015"),
				URI.create("https://www.blake2.net/"),
				URI.create("https://electriccoin.co/blog/new-snark-curve/"),
				List.of(KeyTypeName.BLS12381_G1,
						KeyTypeName.BLS12381_G2),
				Map.of(KeyTypeName.BLS12381_G1, List.of(JWSAlgorithm.BBSPlus),
						KeyTypeName.BLS12381_G2, List.of(JWSAlgorithm.BBSPlus)));
	}
}
