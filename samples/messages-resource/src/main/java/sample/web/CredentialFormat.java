package sample.web;

import com.fasterxml.jackson.annotation.JsonProperty;

public enum CredentialFormat {
	@JsonProperty("jwt_vc")
	JWT_VC
}
