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
package org.springframework.security.oauth2.core;


import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationServerMetadata;

import java.net.URL;
import java.util.List;

/**
 * A {@link ClaimAccessor} for the "claims" that can be returned
 * in the OAuth 2.0 Authorization Server Metadata Response.
 *
 * @author Daniel Garnier-Moiroux
 * @since 0.1.0
 * @see ClaimAccessor
 * @see AuthorizationServerMetadataClaimAccessor
 * @see OAuth2AuthorizationServerMetadataClaimNames
 * @see OAuth2AuthorizationServerMetadata
 * @see <a target="_blank" href="https://tools.ietf.org/html/rfc8414#section-2">2. Authorization Server Metadata</a>
 */
public interface OAuth2AuthorizationServerMetadataClaimAccessor extends AuthorizationServerMetadataClaimAccessor {

	/**
	 * Returns the {@code URL} of the OAuth 2.0 Token Revocation Endpoint {@code (revocation_endpoint)}.
	 *
	 * @return the {@code URL} of the OAuth 2.0 Token Revocation Endpoint
	 */
	default URL getTokenRevocationEndpoint() {
		return this.getClaimAsURL(OAuth2AuthorizationServerMetadataClaimNames.REVOCATION_ENDPOINT);
	}

	/**
	 * Returns the client authentication methods supported by the OAuth 2.0 Token Revocation Endpoint {@code (revocation_endpoint_auth_methods_supported)}.
	 *
	 * @return the client authentication methods supported by the OAuth 2.0 Token Revocation Endpoint
	 */
	default List<String> getTokenRevocationEndpointAuthenticationMethods() {
		return this.getClaimAsStringList(OAuth2AuthorizationServerMetadataClaimNames.REVOCATION_ENDPOINT_AUTH_METHODS_SUPPORTED);
	}

	/**
	 * Returns the Proof Key for Code Exchange (PKCE) code challenge methods supported by the
	 * OAuth 2.0 Authorization Server {@code (code_challenge_methods_supported)}.
	 *
	 * @return the code challenge methods supported by the OAuth 2.0 Authorization Server
	 */
	default List<String> getCodeChallengeMethods() {
		return this.getClaimAsStringList(OAuth2AuthorizationServerMetadataClaimNames.CODE_CHALLENGE_METHODS_SUPPORTED);
	}
}
