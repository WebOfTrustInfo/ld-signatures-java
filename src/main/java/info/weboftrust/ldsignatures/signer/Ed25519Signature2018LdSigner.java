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
import info.weboftrust.ldsignatures.suites.SignatureSuites;
import info.weboftrust.ldsignatures.util.JWSUtil;

import java.security.GeneralSecurityException;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

public class Ed25519Signature2018LdSigner extends LdSigner<Ed25519Signature2018SignatureSuite> {

	public Ed25519Signature2018LdSigner(ByteSigner signer) {

		super(SignatureSuites.SIGNATURE_SUITE_ED25519SIGNATURE2018, signer);
	}

	public Ed25519Signature2018LdSigner(byte[] privateKey) {

		this(new Ed25519_EdDSA_PrivateKeySigner(privateKey));
	}

	public Ed25519Signature2018LdSigner() {

		this((ByteSigner) null);
	}

	public static void sign(LdProof.Builder ldProofBuilder, byte[] signingInput, ByteSigner signer) throws GeneralSecurityException {

		// build the JWS and sign

		String jws;

		try {

			JWSHeader jwsHeader = new JWSHeader.Builder(JWSAlgorithm.EdDSA).base64URLEncodePayload(false).criticalParams(Collections.singleton("b64")).build();
			byte[] jwsSigningInput = JWSUtil.getJwsSigningInput(jwsHeader, signingInput);

			JWSSigner jwsSigner = new JWSSignerAdapter(signer, JWSAlgorithm.EdDSA);
			Base64URL signature = jwsSigner.sign(jwsHeader, jwsSigningInput);
			jws = JWSUtil.serializeDetachedJws(jwsHeader, signature);
		} catch (JOSEException ex) {

			throw new GeneralSecurityException("JOSE signing problem: " + ex.getMessage(), ex);
		}

		// done

		ldProofBuilder.jws(jws);
	}

	@Override
	public void sign(LdProof.Builder ldProofBuilder, byte[] signingInput) throws GeneralSecurityException {

		sign(ldProofBuilder, signingInput, this.getSigner());
	}
}
