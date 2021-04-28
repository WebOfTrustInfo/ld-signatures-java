package info.weboftrust.ldsignatures.crypto.jose;

import com.nimbusds.jose.jwk.Curve;

public class Curves {

    public static final Curve BLS12381_G1 = new Curve("BLS12381_G1", "BLS12381_G1", null);
    public static final Curve BLS12381_G2 = new Curve("BLS12381_G2", "BLS12381_G2", null);
}
