/*
 * Copyright 2020 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package sample.web;

import org.springframework.http.MediaType;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import javax.validation.Valid;
import java.util.StringJoiner;

/**
 * @author Grzegorz
 * @since 0.0.1
 */
@RestController
public class CredentialController {

	@PostMapping(value = "/credential",
			consumes = MediaType.APPLICATION_JSON_VALUE,
			produces = MediaType.APPLICATION_JSON_VALUE)

	public CredentialResponse getVc(
			@AuthenticationPrincipal String userId,
			Authentication authentication,
			@Valid @RequestBody CredentialRequest credentialRequest
	) {

		StringJoiner allowedCredentialTypes = new StringJoiner(" ");
		for (GrantedAuthority authority : authentication.getAuthorities()) {
			allowedCredentialTypes.add(authority.getAuthority());
		}

		// TODO verify pop
		// TODO verify requested credential type vs allowed credential types

		return new CredentialResponse(credentialRequest.credentialFormat, "LUpixVCWJk0eOt4CXQe1NXK....WZwmhmn9OQp6YxX0a2L " + userId + " " + credentialRequest.credentialType, "fGFF7UkhLa", 6661);
	}
}
