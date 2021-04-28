package info.weboftrust.ldsignatures.crypto.jose;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.Requirement;

public class JWSAlgorithms {

    public static final JWSAlgorithm BBSPlus = new JWSAlgorithm("BBSPlus", Requirement.OPTIONAL);
}
