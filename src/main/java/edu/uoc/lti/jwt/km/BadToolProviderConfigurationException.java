package edu.uoc.lti.jwt.km;

/**
 * @author xaracil@uoc.edu
 */
public class BadToolProviderConfigurationException extends RuntimeException {
	public BadToolProviderConfigurationException(String message) {
		super(message);
	}

	public BadToolProviderConfigurationException(Throwable cause) {
		super(cause);
	}
}
