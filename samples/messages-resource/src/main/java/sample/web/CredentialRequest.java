package sample.web;

import com.fasterxml.jackson.annotation.JsonProperty;

public class CredentialRequest {
	final String credentialType;
	final CredentialFormat credentialFormat;
	final ProofOfPossession proof;

	@JsonProperty("type")
	public String getCredentialType() {
		return credentialType;
	}

	@JsonProperty("format")
	public CredentialFormat getCredentialFormat() {
		return credentialFormat;
	}

	@JsonProperty("proof")
	public ProofOfPossession getProof() {
		return proof;
	}

	public CredentialRequest(
			@JsonProperty("type") final String credentialType,
			@JsonProperty("format") final CredentialFormat format,
			@JsonProperty("proof") final ProofOfPossession proof) {
		this.credentialType = credentialType;
		this.credentialFormat = format;
		this.proof = proof;
	}
}
