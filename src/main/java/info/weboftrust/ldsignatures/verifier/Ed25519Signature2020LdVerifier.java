package info.weboftrust.ldsignatures.verifier;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.JWSVerifier;
import info.weboftrust.ldsignatures.LdProof;
import info.weboftrust.ldsignatures.crypto.ByteVerifier;
import info.weboftrust.ldsignatures.crypto.adapter.JWSVerifierAdapter;
import info.weboftrust.ldsignatures.crypto.impl.Ed25519_EdDSA_PublicKeyVerifier;
import info.weboftrust.ldsignatures.crypto.jose.JWSAlgorithms;
import info.weboftrust.ldsignatures.suites.Ed25519Signature2018SignatureSuite;
import info.weboftrust.ldsignatures.suites.SignatureSuites;
import info.weboftrust.ldsignatures.util.JWSUtil;
import io.ipfs.multibase.Multibase;

import java.security.GeneralSecurityException;
import java.text.ParseException;

public class Ed25519Signature2020LdVerifier extends LdVerifier<Ed25519Signature2018SignatureSuite> {

	public Ed25519Signature2020LdVerifier(ByteVerifier verifier) {

		super(SignatureSuites.SIGNATURE_SUITE_ED25519SIGNATURE2018, verifier);
	}

	public Ed25519Signature2020LdVerifier(byte[] publicKey) {

		this(new Ed25519_EdDSA_PublicKeyVerifier(publicKey));
	}

	public Ed25519Signature2020LdVerifier() {

		this((ByteVerifier) null);
	}

	public static boolean verify(byte[] signingInput, LdProof ldProof, ByteVerifier verifier) throws GeneralSecurityException {

		// verify

		String proofValue = ldProof.getProofValue();
		boolean verify;

		byte[] bytes = Multibase.decode(proofValue);
		verify = verifier.verify(signingInput, bytes, JWSAlgorithm.EdDSA.getName());

		// done

		return verify;
	}

	@Override
	public boolean verify(byte[] signingInput, LdProof ldProof) throws GeneralSecurityException {

		return verify(signingInput, ldProof, this.getVerifier());
	}
}
