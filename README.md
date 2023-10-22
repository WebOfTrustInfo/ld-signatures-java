# ld-signatures-java

## Information

This is an implementation of the following cryptographic suites for [Linked Data Proofs](https://w3c-ccg.github.io/ld-proofs/):

 - [Ed25519Signature2018](https://w3c-ccg.github.io/lds-ed25519-2018/)
 - [Ed25519Signature2020](https://w3c-ccg.github.io/lds-ed25519-2020/)
 - [EcdsaSecp256k1Signature2019](https://w3c-ccg.github.io/lds-ecdsa-secp256k1-2019/)
 - [RsaSignature2018](https://w3c-ccg.github.io/lds-rsa2018/)
 - [JsonWebSignature2020](https://w3c-ccg.github.io/lds-jws2020/)
 - [JcsEd25519Signature2020](https://identity.foundation/JcsEd25519Signature2020/)
 - JcsEcdsaSecp256k1Signature2019

## Maven

Build:

	mvn clean install

Dependency:

	<repositories>
		<repository>
			<id>danubetech-maven-public</id>
			<url>https://repo.danubetech.com/repository/maven-public/</url>
		</repository>
	</repositories>

	<dependency>
		<groupId>info.weboftrust</groupId>
		<artifactId>ld-signatures-java</artifactId>
		<version>1.6.0</version>
	</dependency>

## Example

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

## About

Danube Tech - https://danubetech.com/

<img align="left" src="https://raw.githubusercontent.com/WebOfTrustInfo/ld-signatures-java/main/docs/logo-wot.png">

Originally built during [Rebooting Web-of-Trust](http://www.weboftrust.info/) in Paris on April 21st 2017.

<br clear="left" />

<img align="left" height="70" src="https://raw.githubusercontent.com/WebOfTrustInfo/ld-signatures-java/main/docs/logo-ngi-essiflab.png">

This software library is part of a project that has received funding from the European Union's Horizon 2020 research and innovation programme under grant agreement No 871932
