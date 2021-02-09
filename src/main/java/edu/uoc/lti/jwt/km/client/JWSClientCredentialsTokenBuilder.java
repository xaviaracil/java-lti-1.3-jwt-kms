package edu.uoc.lti.jwt.km.client;

import edu.uoc.lti.jwt.km.kms.JwtKMSBuilder;
import lombok.RequiredArgsConstructor;

import java.util.Date;
import java.util.UUID;

import edu.uoc.lti.clientcredentials.ClientCredentialsRequest;
import edu.uoc.lti.clientcredentials.ClientCredentialsTokenBuilder;

/**
 * @author xaracil@uoc.edu
 */
@RequiredArgsConstructor
public class JWSClientCredentialsTokenBuilder implements ClientCredentialsTokenBuilder {

	private final static long _5_MINUTES = 5 * 30 * 1000;

	private final String keyArn;
	private final String region;

	@Override
	public String build(ClientCredentialsRequest request) {
		return new JwtKMSBuilder(keyArn, region)
						//.setHeaderParam("kid", request.getKid())
						.setHeaderParam("typ", "JWT")
						.setIssuer(request.getClientId())
						.setSubject(request.getClientId())
						.setAudience(request.getOauth2Url())
						.setIssuedAt(new Date())
						.setExpiration(new Date(System.currentTimeMillis() + _5_MINUTES))
						.setId(UUID.randomUUID().toString())
						.compact();
	}
}
