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

import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationResponseType;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.core.Version;
import org.springframework.util.Assert;

import java.io.Serializable;
import java.net.URI;
import java.net.URL;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Consumer;
import java.util.stream.Collectors;


/**
 * A base representation of a Provider Metadata response, returned by an endpoint defined
 * either in OpenID Connect Discovery 1.0 or OAuth 2.0 Authorization Server Metadata.
 * It contains a set of claims about the Provider's configuration.
 *
 * @author Daniel Garnier-Moiroux
 * @since 0.1.0
 * @see AuthorizationServerMetadataClaimAccessor
 * @see <a target="_blank" href="https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfigurationResponse">4.2. OpenID Provider Configuration Response</a>
 * @see <a target="_blank" href="https://tools.ietf.org/html/rfc8414#section-3.2">3.2. Authorization Server Metadata Response</a>
 */
public abstract class AbstractAuthorizationServerMetadata implements AuthorizationServerMetadataClaimAccessor, Serializable {
	private static final long serialVersionUID = Version.SERIAL_VERSION_UID;

	protected final Map<String, Object> claims;

	protected AbstractAuthorizationServerMetadata(Map<String, Object> claims) {
		Assert.notEmpty(claims, "claims cannot be empty");
		this.claims = Collections.unmodifiableMap(new LinkedHashMap<>(claims));
	}

	/**
	 * Returns the Authorization Server metadata.
	 *
	 * @return a {@code Map} of the metadata values
	 */
	@Override
	public Map<String, Object> getClaims() {
		return this.claims;
	}

	protected static Map<String, Object> defaultClaims() {
		LinkedHashMap<String, Object> claims = new LinkedHashMap<>();
		claims.put(
				AuthorizationServerMetadataClaimNames.TOKEN_ENDPOINT_AUTH_METHODS_SUPPORTED,
				Arrays.asList(
						"client_secret_basic", 	// TODO: Use ClientAuthenticationMethod.CLIENT_SECRET_BASIC in Spring Security 5.5.0
						"client_secret_post" 	// TODO: Use ClientAuthenticationMethod.CLIENT_SECRET_POST in Spring Security 5.5.0
				)
		);
		claims.put(
				AuthorizationServerMetadataClaimNames.GRANT_TYPES_SUPPORTED,
				Arrays.asList(
						AuthorizationGrantType.AUTHORIZATION_CODE.getValue(),
						AuthorizationGrantType.CLIENT_CREDENTIALS.getValue(),
						AuthorizationGrantType.REFRESH_TOKEN.getValue()
				)
		);
		claims.put(
				AuthorizationServerMetadataClaimNames.RESPONSE_TYPES_SUPPORTED,
				Collections.singletonList(OAuth2AuthorizationResponseType.CODE.getValue())
		);
		claims.put(
				AuthorizationServerMetadataClaimNames.SCOPES_SUPPORTED,
				Collections.singletonList(OidcScopes.OPENID)
		);
		return claims;
	}

	/**
	 * An abstract builder for subclasses of {@link AbstractAuthorizationServerMetadata}.
	 */
	public static abstract class AbstractBuilder<T extends AbstractAuthorizationServerMetadata, B extends AbstractBuilder<T, B>> {

		protected final Map<String, Object> claims = new LinkedHashMap<>();

		protected AbstractBuilder() { }

		protected abstract B getThis();	// avoid unchecked casts in subclasses by using "getThis()" instead of "(B) this"

		/**
		 * Use this {@code issuer} in the resulting {@link AbstractAuthorizationServerMetadata}, REQUIRED.
		 *
		 * @param issuer the {@code URL} of the Authorization Server's Issuer Identifier
		 * @return the {@link AbstractBuilder} for further configuration
		 */
		public B issuer(String issuer) {
			return claim(AuthorizationServerMetadataClaimNames.ISSUER, issuer);
		}

		/**
		 * Use this {@code authorization_endpoint} in the resulting {@link AbstractAuthorizationServerMetadata}, REQUIRED.
		 *
		 * @param authorizationEndpoint the {@code URL} of the Authorization Server's OAuth 2.0 Authorization Endpoint
		 * @return the {@link AbstractBuilder} for further configuration
		 */
		public B authorizationEndpoint(String authorizationEndpoint) {
			return claim(AuthorizationServerMetadataClaimNames.AUTHORIZATION_ENDPOINT, authorizationEndpoint);
		}

		/**
		 * Use this {@code token_endpoint} in the resulting {@link AbstractAuthorizationServerMetadata}, REQUIRED.
		 *
		 * @param tokenEndpoint the {@code URL} of the Authorization Server's OAuth 2.0 Token Endpoint
		 * @return the {@link AbstractBuilder} for further configuration
		 */
		public B tokenEndpoint(String tokenEndpoint) {
			return claim(AuthorizationServerMetadataClaimNames.TOKEN_ENDPOINT, tokenEndpoint);
		}

		/**
		 * Add this Authentication Method to the collection of {@code token_endpoint_auth_methods_supported}
		 * in the resulting {@link AbstractAuthorizationServerMetadata}, OPTIONAL.
		 *
		 * @param authenticationMethod the OAuth 2.0 Authentication Method supported by the Token Endpoint
		 * @return the {@link AbstractBuilder} for further configuration
		 */
		public B tokenEndpointAuthenticationMethod(String authenticationMethod) {
			addClaimToClaimList(AuthorizationServerMetadataClaimNames.TOKEN_ENDPOINT_AUTH_METHODS_SUPPORTED, authenticationMethod);
			return getThis();
		}

		/**
		 * A {@code Consumer} of the Token Endpoint Authentication Method(s) allowing the ability to add, replace, or remove.
		 *
		 * @param authenticationMethodsConsumer a {@code Consumer} of the Token Endpoint Authentication Method(s)
		 * @return the {@link AbstractBuilder} for further configuration
		 */
		public B tokenEndpointAuthenticationMethods(Consumer<List<String>> authenticationMethodsConsumer) {
			acceptClaimValues(AuthorizationServerMetadataClaimNames.TOKEN_ENDPOINT_AUTH_METHODS_SUPPORTED, authenticationMethodsConsumer);
			return getThis();
		}

		/**
		 * Use this {@code jwks_uri} in the resulting {@link AbstractAuthorizationServerMetadata}, REQUIRED.
		 *
		 * @param jwkSetUri the {@code URL} of the Authorization Server's JSON Web Key Set document
		 * @return the {@link AbstractBuilder} for further configuration
		 */
		public B jwkSetUri(String jwkSetUri) {
			return claim(AuthorizationServerMetadataClaimNames.JWKS_URI, jwkSetUri);
		}

		/**
		 * Add this Response Type to the collection of {@code response_types_supported} in the resulting
		 * {@link AbstractAuthorizationServerMetadata}.
		 *
		 * @param responseType the OAuth 2.0 {@code response_type} value that the Authorization Server supports
		 * @return the {@link AbstractBuilder} for further configuration
		 */
		public B responseType(String responseType) {
			addClaimToClaimList(AuthorizationServerMetadataClaimNames.RESPONSE_TYPES_SUPPORTED, responseType);
			return getThis();
		}

		/**
		 * A {@code Consumer} of the Response Type(s) allowing the ability to add, replace, or remove.
		 *
		 * @param responseTypesConsumer a {@code Consumer} of the Response Type(s)
		 * @return the {@link AbstractBuilder} for further configuration
		 */
		public B responseTypes(Consumer<List<String>> responseTypesConsumer) {
			acceptClaimValues(AuthorizationServerMetadataClaimNames.RESPONSE_TYPES_SUPPORTED, responseTypesConsumer);
			return getThis();
		}

		/**
		 * Add this Grant Type to the collection of {@code grant_types_supported} in the resulting
		 * {@link AbstractAuthorizationServerMetadata}, OPTIONAL.
		 *
		 * @param grantType the OAuth 2.0 {@code grant_type} value that the Authorization Server supports
		 * @return the {@link AbstractBuilder} for further configuration
		 */
		public B grantType(String grantType) {
			addClaimToClaimList(AuthorizationServerMetadataClaimNames.GRANT_TYPES_SUPPORTED, grantType);
			return getThis();
		}

		/**
		 * A {@code Consumer} of the Grant Type(s) allowing the ability to add, replace, or remove.
		 *
		 * @param grantTypesConsumer a {@code Consumer} of the Grant Type(s)
		 * @return the {@link AbstractBuilder} for further configuration
		 */
		public B grantTypes(Consumer<List<String>> grantTypesConsumer) {
			acceptClaimValues(AuthorizationServerMetadataClaimNames.GRANT_TYPES_SUPPORTED, grantTypesConsumer);
			return getThis();
		}

		/**
		 * Add this Scope to the collection of {@code scopes_supported} in the resulting
		 * {@link AbstractAuthorizationServerMetadata}, RECOMMENDED.
		 *
		 * @param scope the OAuth 2.0 {@code scope} value that the Authorization Server supports
		 * @return the {@link AbstractBuilder} for further configuration
		 */
		public B scope(String scope) {
			addClaimToClaimList(AuthorizationServerMetadataClaimNames.SCOPES_SUPPORTED, scope);
			return getThis();
		}

		/**
		 * A {@code Consumer} of the Scopes(s) allowing the ability to add, replace, or remove.
		 *
		 * @param scopesConsumer a {@code Consumer} of the Scopes(s)
		 * @return the {@link AbstractBuilder} for further configuration
		 */
		public B scopes(Consumer<List<String>> scopesConsumer) {
			acceptClaimValues(AuthorizationServerMetadataClaimNames.SCOPES_SUPPORTED, scopesConsumer);
			return getThis();
		}

		/**
		 * Use this claim in the resulting {@link AbstractAuthorizationServerMetadata}
		 *
		 * @param name the claim name
		 * @param value the claim value
		 * @return the {@link AbstractBuilder} for further configuration
		 */
		public B claim(String name, Object value) {
			Assert.hasText(name, "name cannot be empty");
			Assert.notNull(value, "value cannot be null");
			this.claims.put(name, value);
			return getThis();
		}

		/**
		 * Provides access to every {@link #claim(String, Object)} declared so far with
		 * the possibility to add, replace, or remove.
		 *
		 * @param claimsConsumer a {@code Consumer} of the claims
		 * @return the {@link AbstractBuilder} for further configurations
		 */
		public B claims(Consumer<Map<String, Object>> claimsConsumer) {
			claimsConsumer.accept(this.claims);
			return getThis();
		}

		/**
		 * Creates the {@link AbstractAuthorizationServerMetadata}.
		 *
		 * @return the {@link AbstractAuthorizationServerMetadata}
		 */
		public abstract T build();

		protected void validateCommonClaims() {
			Assert.notNull(this.claims.get(AuthorizationServerMetadataClaimNames.ISSUER), "issuer cannot be null");
			validateURL(this.claims.get(AuthorizationServerMetadataClaimNames.ISSUER), "issuer must be a valid URL");
			Assert.notNull(this.claims.get(AuthorizationServerMetadataClaimNames.AUTHORIZATION_ENDPOINT), "authorizationEndpoint cannot be null");
			validateURL(this.claims.get(AuthorizationServerMetadataClaimNames.AUTHORIZATION_ENDPOINT), "authorizationEndpoint must be a valid URL");
			Assert.notNull(this.claims.get(AuthorizationServerMetadataClaimNames.TOKEN_ENDPOINT), "tokenEndpoint cannot be null");
			validateURL(this.claims.get(AuthorizationServerMetadataClaimNames.TOKEN_ENDPOINT), "tokenEndpoint must be a valid URL");
			Assert.notNull(this.claims.get(AuthorizationServerMetadataClaimNames.JWKS_URI), "jwksUri cannot be null");
			validateURL(this.claims.get(AuthorizationServerMetadataClaimNames.JWKS_URI), "jwksUri must be a valid URL");
			Assert.notNull(this.claims.get(AuthorizationServerMetadataClaimNames.RESPONSE_TYPES_SUPPORTED), "responseTypes cannot be null");
			Assert.isInstanceOf(List.class, this.claims.get(AuthorizationServerMetadataClaimNames.RESPONSE_TYPES_SUPPORTED), "responseTypes must be of type List");
			Assert.notEmpty((List<?>) this.claims.get(AuthorizationServerMetadataClaimNames.RESPONSE_TYPES_SUPPORTED), "responseTypes cannot be empty");
		}

		/**
		 * Remove claims of type Collection that have a size of zero.
		 * <p>
		 * Both <a target="_blank" href="https://tools.ietf.org/html/rfc8414#section-3.2">3.2. Authorization Server Metadata Response</a>
		 * and <a target="_blank" href="https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfigurationResponse">4.2. OpenID Provider Configuration Response</a>
		 * state "Claims with zero elements MUST be omitted from the response."
		 */
		protected void removeEmptyClaims() {
			Set<String> claimsToRemove = this.claims.entrySet()
					.stream()
					.filter(entry -> entry.getValue() != null)
					.filter(entry -> Collection.class.isAssignableFrom(entry.getValue().getClass()))
					.filter(entry -> ((Collection<?>) entry.getValue()).size() == 0)
					.map(Map.Entry::getKey)
					.collect(Collectors.toSet());

			for (String claimToRemove : claimsToRemove) {
				this.claims.remove(claimToRemove);
			}
		}

		protected static void validateURL(Object url, String errorMessage) {
			if (URL.class.isAssignableFrom(url.getClass())) {
				return;
			}

			try {
				new URI(url.toString()).toURL();
			} catch (Exception ex) {
				throw new IllegalArgumentException(errorMessage, ex);
			}
		}

		@SuppressWarnings("unchecked")
		protected void addClaimToClaimList(String name, String value) {
			Assert.hasText(name, "name cannot be empty");
			Assert.notNull(value, "value cannot be null");
			this.claims.computeIfAbsent(name, k -> new LinkedList<String>());
			((List<String>) this.claims.get(name)).add(value);
		}

		@SuppressWarnings("unchecked")
		protected void acceptClaimValues(String name, Consumer<List<String>> valuesConsumer) {
			Assert.hasText(name, "name cannot be empty");
			Assert.notNull(valuesConsumer, "valuesConsumer cannot be null");
			this.claims.computeIfAbsent(name, k -> new LinkedList<String>());
			List<String> values = (List<String>) this.claims.get(name);
			valuesConsumer.accept(values);
		}
	}
}
