package info.weboftrust.ldsignatures.signer;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.util.Base64URL;
import info.weboftrust.ldsignatures.LdProof;
import info.weboftrust.ldsignatures.crypto.ByteSigner;
import info.weboftrust.ldsignatures.crypto.adapter.JWSSignerAdapter;
import info.weboftrust.ldsignatures.crypto.impl.Ed25519_EdDSA_PrivateKeySigner;
import info.weboftrust.ldsignatures.jsonld.LDSecurityKeywords;
import info.weboftrust.ldsignatures.suites.Ed25519Signature2018SignatureSuite;
import info.weboftrust.ldsignatures.suites.Ed25519Signature2020SignatureSuite;
import info.weboftrust.ldsignatures.suites.SignatureSuites;
import info.weboftrust.ldsignatures.util.JWSUtil;
import io.ipfs.multibase.Multibase;

import java.security.GeneralSecurityException;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

public class Ed25519Signature2020LdSigner extends LdSigner<Ed25519Signature2020SignatureSuite> {

	public Ed25519Signature2020LdSigner(ByteSigner signer) {

		super(SignatureSuites.SIGNATURE_SUITE_ED25519SIGNATURE2020, signer);
	}

	public Ed25519Signature2020LdSigner(byte[] privateKey) {

		this(new Ed25519_EdDSA_PrivateKeySigner(privateKey));
	}

	public Ed25519Signature2020LdSigner() {

		this((ByteSigner) null);
	}

	public static void sign(LdProof.Builder ldProofBuilder, byte[] signingInput, ByteSigner signer) throws GeneralSecurityException {

		// sign

		String proofValue;

		byte[] bytes = signer.sign(signingInput, JWSAlgorithm.EdDSA.getName());
		proofValue = Multibase.encode(Multibase.Base.Base58BTC, bytes);

		// done

		ldProofBuilder.proofValue(proofValue);
	}

	@Override
	public void sign(LdProof.Builder ldProofBuilder, byte[] signingInput) throws GeneralSecurityException {

		sign(ldProofBuilder, signingInput, this.getSigner());
	}
}
