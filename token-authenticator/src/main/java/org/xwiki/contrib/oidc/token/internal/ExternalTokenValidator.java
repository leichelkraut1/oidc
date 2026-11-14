/*
 * See the NOTICE file distributed with this work for additional
 * information regarding copyright ownership.
 *
 * This is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this software; if not, write to the Free
 * Software Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
 * 02110-1301 USA, or see the FSF site: http://www.fsf.org.
 */
package org.xwiki.contrib.oidc.token.internal;

import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

import javax.inject.Inject;
import javax.inject.Singleton;

import org.apache.commons.lang3.StringUtils;
import org.xwiki.component.annotation.Component;

import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.jwk.source.JWKSourceBuilder;
import com.nimbusds.jose.proc.DefaultJOSEObjectTypeVerifier;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jose.util.DefaultResourceRetriever;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.JWTParser;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.jwt.proc.ConfigurableJWTProcessor;
import com.nimbusds.jwt.proc.DefaultJWTClaimsVerifier;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata;

/**
 * Validates an access token issued by an external OAuth2/OpenID Connect provider: a signed JWT from one of the
 * configured issuers, verified with the keys the issuer publishes, not expired, for one of the configured audiences
 * and with the configured scopes.
 *
 * @version $Id$
 * @since 2.31.0
 */
@Component(roles = ExternalTokenValidator.class)
@Singleton
public class ExternalTokenValidator
{
    private static final Set<JWSAlgorithm> ALGORITHMS = new HashSet<>();

    static {
        ALGORITHMS.addAll(JWSAlgorithm.Family.RSA);
        ALGORITHMS.addAll(JWSAlgorithm.Family.EC);
    }

    // Fetching the issuer's metadata and keys must never block the requests waiting for them for long.
    private static final int HTTP_TIMEOUT = 5000;

    private static final int JWKS_SIZE_LIMIT = 512 * 1024;

    // The JWT claims holding the granted scopes: "scope" (RFC 9068) or "scp" (Microsoft Entra ID).
    private static final List<String> SCOPE_CLAIMS = Arrays.asList("scope", "scp");

    @Inject
    private TokenAuthenticatorConfiguration configuration;

    private final Map<String, ConfigurableJWTProcessor<SecurityContext>> processors = new ConcurrentHashMap<>();

    /**
     * @param authorization the value of the HTTP Authorization header
     * @return the claims of the valid token, or {@code null} when the header does not carry an access token of a
     *         configured issuer
     * @throws Exception when the token is from a configured issuer but is not valid
     */
    public JWTClaimsSet validate(String authorization) throws Exception
    {
        List<String> issuers = this.configuration.getExternalIssuers();
        if (issuers.isEmpty() || StringUtils.isEmpty(authorization)) {
            return null;
        }

        // Not a bearer token or not a signed JWT (an access token issued by this wiki, for example): not ours.
        JWT jwt;
        try {
            jwt = JWTParser.parse(BearerAccessToken.parse(authorization).getValue());
        } catch (Exception e) {
            return null;
        }

        if (!(jwt instanceof SignedJWT)) {
            return null;
        }

        // The issuer is unverified until the token is processed: it is only used to pick the issuer's keys.
        String issuer = jwt.getJWTClaimsSet().getIssuer();
        if (!issuers.contains(issuer)) {
            return null;
        }

        JWTClaimsSet claims = getProcessor(issuer).process((SignedJWT) jwt, null);

        checkScopes(claims);

        return claims;
    }

    private ConfigurableJWTProcessor<SecurityContext> getProcessor(String issuer)
    {
        // A failure (provider unreachable) is not cached: the next request tries again.
        return this.processors.computeIfAbsent(issuer, this::createProcessor);
    }

    private ConfigurableJWTProcessor<SecurityContext> createProcessor(String issuer)
    {
        try {
            OIDCProviderMetadata metadata =
                OIDCProviderMetadata.resolve(new Issuer(issuer), HTTP_TIMEOUT, HTTP_TIMEOUT);
            // Caches the keys and fetches them again when a token is signed with an unknown key (key rotation).
            JWKSource<SecurityContext> keys = JWKSourceBuilder
                .create(metadata.getJWKSetURI().toURL(),
                    new DefaultResourceRetriever(HTTP_TIMEOUT, HTTP_TIMEOUT, JWKS_SIZE_LIMIT))
                .retrying(true).build();

            DefaultJWTProcessor<SecurityContext> processor = new DefaultJWTProcessor<>();
            // Microsoft Entra ID access tokens are typed "JWT", RFC 9068 ones "at+jwt".
            processor.setJWSTypeVerifier(
                new DefaultJOSEObjectTypeVerifier<>(JOSEObjectType.JWT, new JOSEObjectType("at+jwt"), null));
            processor.setJWSKeySelector(new JWSVerificationKeySelector<>(ALGORITHMS, keys));
            // Checks the expiration and not-before times too (with a minute of clock skew).
            processor.setJWTClaimsSetVerifier(new DefaultJWTClaimsVerifier<>(
                new HashSet<>(this.configuration.getExternalAudiences()),
                new JWTClaimsSet.Builder().issuer(issuer).build(), new HashSet<>(Arrays.asList("sub", "exp")),
                null));

            return processor;
        } catch (Exception e) {
            throw new IllegalStateException(String.format("Failed to get the keys of issuer [%s]", issuer), e);
        }
    }

    private void checkScopes(JWTClaimsSet claims)
    {
        List<String> required = this.configuration.getExternalScopes();
        if (required.isEmpty()) {
            return;
        }

        Set<String> granted = new HashSet<>();
        for (String claim : SCOPE_CLAIMS) {
            Object value = claims.getClaim(claim);
            if (value instanceof String) {
                granted.addAll(Arrays.asList(StringUtils.split((String) value)));
            } else if (value instanceof List) {
                ((List<?>) value).forEach(scope -> granted.add(String.valueOf(scope)));
            }
        }

        if (!granted.containsAll(required)) {
            throw new IllegalArgumentException(
                String.format("The token lacks the required scopes %s (it has %s)", required, granted));
        }
    }
}
