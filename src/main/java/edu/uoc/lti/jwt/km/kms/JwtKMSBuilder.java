package edu.uoc.lti.jwt.km.kms;

import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.impl.crypto.JwtSigner;

import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;

/**
 * Universitat Oberta de Catalunya
 * Made for the project lti-13-jwt
 */
public class JwtKMSBuilder extends io.jsonwebtoken.impl.DefaultJwtBuilder {
	private final String arn;
	private final String region;

	public JwtKMSBuilder(String arn, String region) {
		this.arn = arn;
		this.region = region;
		this.signWith(fakePrivateKey(), SignatureAlgorithm.RS256);
	}


	@Override
	protected JwtSigner createSigner(SignatureAlgorithm alg, Key key) {
		return new KMSSigner(arn, region);
	}

	private Key fakePrivateKey() {
		KeyPairGenerator kpg = null;
		try {
			kpg = KeyPairGenerator
							.getInstance("RSA");
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}

		// initializing with 2048
		kpg.initialize(2048);

		// getting key pairs
		// using generateKeyPair() method
		KeyPair kp = kpg.genKeyPair();

		// getting public key
		return kp.getPrivate();
	}
}
