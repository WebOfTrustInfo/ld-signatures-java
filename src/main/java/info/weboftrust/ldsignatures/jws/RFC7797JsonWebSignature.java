package info.weboftrust.ldsignatures.jws;

import org.jose4j.jws.JsonWebSignature;

/**
 * @deprecated
 * This is now natively supported by jose4j
 */
@Deprecated
public class RFC7797JsonWebSignature extends JsonWebSignature {

	private String fixedHeader;
	private String unencodedPayload;

	public RFC7797JsonWebSignature(String fixedHeader, String unencodedPayload) {

		this.fixedHeader = fixedHeader;
		this.unencodedPayload = unencodedPayload;
	}

	@Override
	public String getEncodedHeader() {

		return base64url.base64UrlEncodeUtf8ByteRepresentation(this.fixedHeader);
	}

	@Override
	public String getEncodedPayload() {

		return this.unencodedPayload;
	}
}
