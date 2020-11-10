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
package org.springframework.security.oauth2.core.endpoint;

import org.springframework.security.oauth2.core.AbstractAuthorizationServerMetadata;
import org.springframework.security.oauth2.core.OAuth2AuthorizationServerMetadataClaimAccessor;
import org.springframework.security.oauth2.core.OAuth2AuthorizationServerMetadataClaimNames;
import org.springframework.security.oauth2.core.Version;
import org.springframework.util.Assert;

import java.io.Serializable;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;

/**
 * A representation of an OAuth 2.0 Authorization Server Metadata response,
 * which is returned form an OAuth 2.0 Authorization Server's Metadata Endpoint,
 * and contains a set of claims about the Authorization Server's configuration.
 * The claims are defined by the OAuth 2.0 Authorization Server Metadata
 * specification (RFC 8414).
 *
 * @author Daniel Garnier-Moiroux
 * @since 0.1.0
 * @see AbstractAuthorizationServerMetadata
 * @see OAuth2AuthorizationServerMetadataClaimAccessor
 * @see <a target="_blank" href="https://tools.ietf.org/html/rfc8414#section-3.2">3.2. Authorization Server Metadata Response</a>
 */
public final class OAuth2AuthorizationServerMetadata extends AbstractAuthorizationServerMetadata
		implements OAuth2AuthorizationServerMetadataClaimAccessor, Serializable {
	private static final long serialVersionUID = Version.SERIAL_VERSION_UID;

	private OAuth2AuthorizationServerMetadata(Map<String, Object> claims) {
		super(claims);
	}

	/**
	 * Constructs a new {@link Builder} with empty claims.
	 *
	 * @return the {@link Builder}
	 */
	public static Builder builder() {
		return new Builder();
	}

	/**
	 * Constructs a new {@link Builder} with the provided claims.
	 *
	 * @param claims the claims to initialize the builder
	 * @return the {@link Builder}
	 */
	public static Builder withClaims(Map<String, Object> claims) {
		Assert.notEmpty(claims, "claims cannot be empty");
		return new Builder()
				.claims(c -> c.putAll(claims));
	}

	/**
	 * Constructs a new {@link Builder} with default claims.
	 *
	 * @return the {@link Builder}
	 */
	public static Builder withDefaultClaims() {
		return new Builder()
				.claims(c -> c.putAll(defaultClaims()))
				.codeChallengeMethod(PkceCodeChallengeMethod2.PLAIN.getValue())
				.codeChallengeMethod(PkceCodeChallengeMethod2.S256.getValue())
				.tokenRevocationEndpointAuthenticationMethod("client_secret_basic") 	// TODO: Use ClientAuthenticationMethod.CLIENT_SECRET_BASIC in Spring Security 5.5.0
				.tokenRevocationEndpointAuthenticationMethod("client_secret_post");	// TODO: Use ClientAuthenticationMethod.CLIENT_SECRET_POST in Spring Security 5.5.0
	}

	/**
	 * Helps configure an {@link OAuth2AuthorizationServerMetadata}.
	 */
	public static class Builder
			extends AbstractAuthorizationServerMetadata.AbstractBuilder<OAuth2AuthorizationServerMetadata, Builder> {
		private Builder() {
		}

		@Override
		protected Builder getThis() {
			return this;
		}

		/**
		 * Use this {@code revocation_endpoint} in the resulting {@link OAuth2AuthorizationServerMetadata}, OPTIONAL.
		 *
		 * @param tokenRevocationEndpoint the {@code URL} of the OAuth 2.0 Authorization Server's Token Revocation Endpoint
		 * @return the {@link Builder} for further configuration
		 */
		public Builder tokenRevocationEndpoint(String tokenRevocationEndpoint) {
			return claim(OAuth2AuthorizationServerMetadataClaimNames.REVOCATION_ENDPOINT, tokenRevocationEndpoint);
		}

		/**
		 * Add this Authentication Method to the collection of {@code revocation_endpoint_auth_methods_supported}
		 * in the resulting {@link OAuth2AuthorizationServerMetadata}, OPTIONAL.
		 *
		 * @param authenticationMethod the OAuth 2.0 Authentication Method supported by the Revocation Endpoint
		 * @return the {@link Builder} for further configuration
		 */
		public Builder tokenRevocationEndpointAuthenticationMethod(String authenticationMethod) {
			addClaimToClaimList(OAuth2AuthorizationServerMetadataClaimNames.REVOCATION_ENDPOINT_AUTH_METHODS_SUPPORTED, authenticationMethod);
			return this;
		}

		/**
		 * A {@code Consumer} of the Token Revocation Endpoint Authentication Method(s) allowing the ability to add,
		 * replace, or remove.
		 *
		 * @param authenticationMethodsConsumer a {@code Consumer} of the OAuth 2.0 Token Revocation Endpoint Authentication Method(s)
		 * @return the {@link Builder} for further configuration
		 */
		public Builder tokenRevocationEndpointAuthenticationMethods(Consumer<List<String>> authenticationMethodsConsumer) {
			acceptClaimValues(OAuth2AuthorizationServerMetadataClaimNames.REVOCATION_ENDPOINT_AUTH_METHODS_SUPPORTED, authenticationMethodsConsumer);
			return this;
		}

		/**
		 * Add this Proof Key for Code Exchange (PKCE) Code Challenge Method to the collection of
		 * {@code code_challenge_methods_supported} in the resulting {@link OAuth2AuthorizationServerMetadata}, OPTIONAL.
		 *
		 * @param codeChallengeMethod the Proof Key for Code Exchange (PKCE) Code Challenge Method
		 * supported by the Authorization Server
		 * @return the {@link Builder} for further configuration
		 */
		public Builder codeChallengeMethod(String codeChallengeMethod) {
			addClaimToClaimList(OAuth2AuthorizationServerMetadataClaimNames.CODE_CHALLENGE_METHODS_SUPPORTED, codeChallengeMethod);
			return this;
		}

		/**
		 * A {@code Consumer} of the Proof Key for Code Exchange (PKCE) Code Challenge Method(s) allowing
		 * the ability to add, replace, or remove.
		 *
		 * @param codeChallengeMethodsConsumer a {@code Consumer} of the Proof Key for Code Exchange (PKCE)
		 * Code Challenge Method(s)
		 * @return the {@link Builder} for further configuration
		 */
		public Builder codeChallengeMethods(Consumer<List<String>> codeChallengeMethodsConsumer) {
			acceptClaimValues(OAuth2AuthorizationServerMetadataClaimNames.CODE_CHALLENGE_METHODS_SUPPORTED, codeChallengeMethodsConsumer);
			return this;
		}

		/**
		 * Validate the claims and build the {@link OAuth2AuthorizationServerMetadata}.
		 * <p>
		 * The following claims are REQUIRED:
		 * {@code issuer}, {@code authorization_endpoint}, {@code token_endpoint},
		 * {@code jwks_uri} and {@code response_types_supported}.
		 *
		 * @return the {@link OAuth2AuthorizationServerMetadata}
		 */
		public OAuth2AuthorizationServerMetadata build() {
			validateCommonClaims();
			validateOAuth2ServerMetadataSpecificClaims();
			removeEmptyClaims();
			return new OAuth2AuthorizationServerMetadata(this.claims);
		}

		private void validateOAuth2ServerMetadataSpecificClaims() {
			if (this.claims.get(OAuth2AuthorizationServerMetadataClaimNames.REVOCATION_ENDPOINT) != null) {
				validateURL(this.claims.get(OAuth2AuthorizationServerMetadataClaimNames.REVOCATION_ENDPOINT), "tokenRevocationEndpoint must be a valid URL");
			}
		}
	}
}
