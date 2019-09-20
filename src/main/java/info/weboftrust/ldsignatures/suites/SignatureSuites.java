package info.weboftrust.ldsignatures.suites;

public class SignatureSuites {

	public static final RsaSignature2018SignatureSuite SIGNATURE_SUITE_RSASIGNATURE2018 = new RsaSignature2018SignatureSuite();
	public static final Ed25519Signature2018SignatureSuite SIGNATURE_SUITE_ED25519SIGNATURE2018 = new Ed25519Signature2018SignatureSuite();
	public static final EcdsaKoblitzSignature2016SignatureSuite SIGNATURE_SUITE_ECDSAKOBLITZSIGNATURE2016 = new EcdsaKoblitzSignature2016SignatureSuite();
	public static final EcdsaSecp256k1Signature2019SignatureSuite SIGNATURE_SUITE_ECDSASECP256L1SIGNATURE2019 = new EcdsaSecp256k1Signature2019SignatureSuite();
}
