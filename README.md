Originally built during [Rebooting Web-of-Trust](http://www.weboftrust.info/) in Paris on April 21st 2017.

![RWoT Logo](https://github.com/WebOfTrustInfo/ld-signatures-java/blob/master/wot-logo.png?raw=true)

### Information

This is a work-in-progress implementation of the following cryptographic suites for [Linked Data Proofs](https://w3c-ccg.github.io/ld-proofs/):

 - [Ed25519Signature2018](https://w3c-ccg.github.io/lds-ed25519-2018/)
 - [EcdsaSecp256k1Signature2019](https://w3c-dvcg.github.io/lds-ecdsa-secp256k1-2019/)
 - [RsaSignature2018](https://w3c-ccg.github.io/lds-rsa2018/)

Highly experimental, incomplete, and not ready for production use! Use at your own risk! Pull requests welcome.

### Maven

Build:

	mvn clean install

Dependency:

	<dependency>
		<groupId>info.weboftrust</groupId>
		<artifactId>ld-signatures-java</artifactId>
		<version>0.3-SNAPSHOT</version>
		<scope>compile</scope>
	</dependency>

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

    JsonLDObject jsonLdObject = JsonLDObject.fromJson(new FileReader("input.jsonld"));

    byte[] testEd25519PrivateKey = Hex.decodeHex("984b589e121040156838303f107e13150be4a80fc5088ccba0b0bdc9b1d89090de8777a28f8da1a74e7a13090ed974d879bf692d001cddee16e4cc9f84b60580".toCharArray());

    Ed25519Signature2018LdSigner signer = new Ed25519Signature2018LdSigner(testEd25519PrivateKey);
    signer.setCreated(new Date());
    signer.setProofPurpose(LDSecurityKeywords.JSONLD_TERM_ASSERTIONMETHOD);
    signer.setVerificationMethod(URI.create("https://example.com/jdoe/keys/1"));
    signer.setDomain("example.com");
    signer.setNonce("343s$FSFDa-");
    LdProof ldProof = signer.sign(jsonLdObject);

    System.out.println(jsonLdObject.toJson(true));

Example Linked Data Proof:

	{
        "type": "Ed25519Signature2018",
        "created": "2020-10-15T09:42:46Z",
        "domain": "example.com",
        "nonce" : "343s$FSFDa-",
        "proofPurpose": "assertionMethod",
        "verificationMethod": "https://example.com/jdoe/keys/1",
        "jws": "eyJiNjQiOmZhbHNlLCJjcml0IjpbImI2NCJdLCJhbGciOiJFZERTQSJ9..8sFJcDtO_pYLjIkJNKfIOL3IOgm_bpbOqqr8ha0ZDa-e6XorbywVQmFCATNXPqMV10deru-zajF79tVelKo-Bw"
    }

### About

Rebooting Web-of-Trust - http://www.weboftrust.info/

Markus Sabadello, Danube Tech - https://danubetech.com/
