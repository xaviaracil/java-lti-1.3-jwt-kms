package edu.uoc.lti.jwt.kms;

import com.amazonaws.services.kms.AWSKMS;
import com.amazonaws.services.kms.AWSKMSClientBuilder;
import com.amazonaws.services.kms.model.SignRequest;
import com.amazonaws.services.kms.model.SignResult;
import com.amazonaws.services.kms.model.SigningAlgorithmSpec;
import io.jsonwebtoken.impl.crypto.JwtSigner;
import io.jsonwebtoken.io.Encoders;
import lombok.RequiredArgsConstructor;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;

/**
 * Universitat Oberta de Catalunya
 * Made for the project lti-13-jwt
 */
@RequiredArgsConstructor
public class KMSSigner implements JwtSigner {
	private final String keyARN;
	private final String region;

	@Override
	public String sign(String jwtWithoutSignature) {

		AWSKMS kmsClient = AWSKMSClientBuilder.standard()
						.withRegion(region)
						.build();

		byte[] bytesToSign = jwtWithoutSignature.getBytes(StandardCharsets.US_ASCII);

		SignRequest signRequest = new SignRequest()
						.withKeyId(keyARN)
						.withSigningAlgorithm(SigningAlgorithmSpec.RSASSA_PKCS1_V1_5_SHA_256)
						.withMessage(ByteBuffer.wrap(bytesToSign));

		final SignResult signResult = kmsClient.sign(signRequest);

		final byte[] signature = new byte[signResult.getSignature().remaining()];
		signResult.getSignature().get(signature);

		return Encoders.BASE64URL.encode(signature);
	}
}
