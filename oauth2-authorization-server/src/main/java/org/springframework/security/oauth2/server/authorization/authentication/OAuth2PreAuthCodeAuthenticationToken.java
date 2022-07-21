/*
 * Copyright 2020-2021 the original author or authors.
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
package org.springframework.security.oauth2.server.authorization.authentication;

import org.springframework.lang.Nullable;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.server.authorization.web.authentication.OAuth2PreAuthCodeAuthenticationConverter;

import java.util.Map;

/**
 * An {@link Authentication} implementation used for the OAuth 2.0 Pre-Authorization Code Grant
 * specified https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html
 *
 * @author Darek Zbik
 * @see OAuth2AuthorizationCodeAuthenticationToken
 */
public class OAuth2PreAuthCodeAuthenticationToken extends OAuth2AuthorizationCodeAuthenticationToken {
	/**
	 * Constructs an {@code OAuth2AuthorizationCodeAuthenticationToken} using the provided parameters.
	 *
	 * @param code the authorization code
	 * @param clientPrincipal the authenticated client principal
	 * @param additionalParameters the additional parameters
	 */
	public OAuth2PreAuthCodeAuthenticationToken(String code, Authentication clientPrincipal,
			@Nullable Map<String, Object> additionalParameters) {
		super(OAuth2PreAuthCodeAuthenticationConverter.PRE_AUTH_CODE_GRANT_TYPE, code, clientPrincipal, null, additionalParameters);
	}
}
