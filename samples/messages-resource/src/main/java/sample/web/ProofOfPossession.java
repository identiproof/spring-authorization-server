package sample.web;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;

public class ProofOfPossession {
	final ProofOfPossessionType proofType;
	final String jwt;

	@JsonCreator
	public ProofOfPossession(
			@JsonProperty("proof_type") final ProofOfPossessionType proofType,
			@JsonProperty("jwt") final String jwt) {
		this.proofType = proofType;
		this.jwt = jwt;
	}
}
