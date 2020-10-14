package info.weboftrust.ldsignatures.crypto.provider.impl;

import info.weboftrust.ldsignatures.crypto.provider.SHA256Provider;

import java.security.GeneralSecurityException;
import java.security.MessageDigest;

public class JavaSHA256Provider extends SHA256Provider {

	@Override
	public byte[] sha256(byte[] bytes) throws GeneralSecurityException {

		MessageDigest md = MessageDigest.getInstance("SHA-256");
		md.update(bytes);
		return md.digest();
	}
}
