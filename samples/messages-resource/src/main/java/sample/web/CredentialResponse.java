package sample.web;

import com.fasterxml.jackson.annotation.JsonProperty;

public class CredentialResponse {
	@JsonProperty("format")
	private final CredentialFormat credentialFormat;
	private final String crecential;
	@JsonProperty("c_nonce")
	private final String nonce;
	@JsonProperty("c_nonce_expires_in")
	private final int expires_in;

	public CredentialFormat getCredentialFormat() {
		return credentialFormat;
	}

	public String getCrecential() {
		return crecential;
	}

	public String getNonce() {
		return nonce;
	}

	public int getExpires_in() {
		return expires_in;
	}

	public CredentialResponse(final CredentialFormat credentialFormat, final String crecential, final String nonce, final int expires_in) {
		this.credentialFormat = credentialFormat;
		this.crecential = crecential;
		this.nonce = nonce;
		this.expires_in = expires_in;
	}
}
