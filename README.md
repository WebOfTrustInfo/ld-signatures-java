Built during [Rebooting Web-of-Trust](http://www.weboftrust.info/) in Paris on April 21st 2017.

![RWoT Logo](https://github.com/WebOfTrustInfo/ld-signatures-java/blob/master/wot-logo.png?raw=true)

### Information

This is a work-in-progress implementation of the [2017 RSA Signature Suite](https://w3c-dvcg.github.io/lds-rsa2017/) for the Linked Data Signatures specification.

Highly experimental, incomplete, and not ready for production use! Use at your own risk! Pull requests welcome.

### Example

Example JSON-LD document:

	{
		"@context": {
			"schema": "http://schema.org/",
			"name": "schema:name",
			"homepage": "schema:url",
			"image": "schema:image"
		},
		"name": "Manu Sporny",
		"homepage": "https://manu.sporny.org/",
		"image": "https://manu.sporny.org/images/manu.png"
	}

Example code:

		LinkedHashMap<String, Object> jsonLdObject = (LinkedHashMap<String, Object>) JsonUtils.fromString(TestUtil.read(JsonLdSignTest.class.getResourceAsStream("sign.test.jsonld")));
		URI creator = URI.create("https://example.com/jdoe/keys/1");
		String created = "2017-10-24T05:33:31Z";
		String domain = "example.com";
		String nonce = null;

		RsaSignature2017LdSigner signer = new RsaSignature2017LdSigner(jsonLdObject, TestUtil.testRSAPrivateKey, creator, created, domain, nonce);
		LdSignature ldSignature = signer.buildLdSignature();

Example Linked Data Signature:

	  "signature" : {
	    "type" : "https://w3id.org/security#SignatureSuite",
	    "creator" : "https://example.com/jdoe/keys/1",
	    "created" : "2017-10-24T05:33:31Z",
	    "domain" : "example.com",
	    "signatureValue" : "eyJhbGciOiJSUzI1NiIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..d8wWxUJTpxAbYHLgFfaYYJJHdWido6wDMBeUhPL7e0m4vuj7xUePbnorf-YqlGZwaGI0zVI_-qJmGbqSB0bm8x20Z9nvawZS8lTk_4uLIPwSPeH8Cyu5bdUP1OIImBhm0gpUmAZfnDVhCgC81lJOaa4tqCjSr940cRUQ9agYjcOyhUBdBOwQgjd8jgkI7vmXqs2m7TmOVY7aAr-6X3AhJqX_a-iD5sdBsoTNulfTyPjEZcFXMvs6gx2078ftwYiUNQzV4qKwkhmUSAINWomKe_fUh4BpdPbsZax7iKYG1hSWRkmrd9R8FllotKQ_nMWZv0urn02F83US62F6ORRT0w"
	  }

### About

Rebooting Web-of-Trust - http://www.weboftrust.info/

Markus Sabadello, Danube Tech -  https://danubetech.com/
