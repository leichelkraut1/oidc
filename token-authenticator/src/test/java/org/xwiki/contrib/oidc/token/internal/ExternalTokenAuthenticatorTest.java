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
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.regex.Pattern;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.xwiki.contrib.oidc.auth.store.OIDCUserStore;
import org.xwiki.contrib.usercommon.formatter.internal.DefaultUserFormatterFactory;
import org.xwiki.model.reference.DocumentReference;
import org.xwiki.model.reference.EntityReference;
import org.xwiki.test.annotation.ComponentList;
import org.xwiki.test.junit5.mockito.ComponentTest;
import org.xwiki.test.junit5.mockito.InjectMockComponents;
import org.xwiki.test.junit5.mockito.MockComponent;

import com.github.tomakehurst.wiremock.WireMockServer;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.xpn.xwiki.doc.XWikiDocument;
import com.xpn.xwiki.objects.BaseObject;
import com.xpn.xwiki.user.api.XWikiUser;

import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.okJson;
import static com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo;
import static com.github.tomakehurst.wiremock.core.WireMockConfiguration.options;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Validate {@link ExternalTokenAuthenticator}.
 *
 * @version $Id$
 */
@ComponentTest
@ComponentList({ ExternalTokenValidator.class, DefaultUserFormatterFactory.class })
class ExternalTokenAuthenticatorTest
{
    private static final String AUDIENCE = "11111111-2222-3333-4444-555555555555";

    private static final String SUBJECT = "jdoe@example.com";

    private static final DocumentReference USER = new DocumentReference("xwiki", "XWiki", "jdoe");

    @InjectMockComponents
    private ExternalTokenAuthenticator authenticator;

    @MockComponent
    private TokenAuthenticatorConfiguration configuration;

    @MockComponent
    private OIDCUserStore userStore;

    private WireMockServer provider;

    private String issuer;

    private RSAKey key;

    private BaseObject userObject;

    @BeforeEach
    void beforeEach() throws Exception
    {
        this.key = new RSAKeyGenerator(2048).keyID("key1").generate();

        this.provider = new WireMockServer(options().dynamicPort());
        this.provider.start();
        this.issuer = "http://localhost:" + this.provider.port() + "/tenant/v2.0";
        this.provider.stubFor(get(urlEqualTo("/tenant/v2.0/.well-known/openid-configuration"))
            .willReturn(okJson("{\"issuer\":\"" + this.issuer + "\",\"authorization_endpoint\":\"" + this.issuer
                + "/authorize\",\"token_endpoint\":\"" + this.issuer + "/token\",\"jwks_uri\":\"" + this.issuer
                + "/keys\",\"response_types_supported\":[\"code\"],\"subject_types_supported\":[\"pairwise\"],"
                + "\"id_token_signing_alg_values_supported\":[\"RS256\"]}")));
        this.provider.stubFor(get(urlEqualTo("/tenant/v2.0/keys"))
            .willReturn(okJson(new JWKSet(this.key.toPublicJWK()).toString())));

        when(this.configuration.getExternalIssuers()).thenReturn(Arrays.asList(this.issuer));
        when(this.configuration.getExternalAudiences()).thenReturn(Arrays.asList(AUDIENCE));
        when(this.configuration.getExternalScopes()).thenReturn(Arrays.asList("access_as_user"));
        // Like the browser sign-in configured for Microsoft Entra ID: the lowercased sign-in name.
        when(this.configuration.getExternalSubjectFormater())
            .thenReturn("${oidc.user.preferredUsername._lowerCase}");
        when(this.configuration.getSubjectForbiddenPattern()).thenReturn(Pattern.compile("\\s"));
        when(this.configuration.getSubjectForbiddenReplacement()).thenReturn("");

        XWikiDocument userDocument = mock(XWikiDocument.class);
        when(userDocument.getDocumentReference()).thenReturn(USER);
        this.userObject = mock(BaseObject.class);
        when(this.userObject.getIntValue(anyString(), anyInt())).thenReturn(1);
        when(userDocument.getXObject(any(EntityReference.class))).thenReturn(this.userObject);
        when(this.userStore.searchDocument(this.issuer, SUBJECT)).thenReturn(userDocument);
    }

    @AfterEach
    void afterEach()
    {
        this.provider.stop();
    }

    private JWTClaimsSet.Builder claims()
    {
        return new JWTClaimsSet.Builder().issuer(this.issuer).audience(AUDIENCE).subject("pairwise-subject")
            .claim("preferred_username", "JDoe@Example.com").claim("scp", "access_as_user")
            .expirationTime(new Date(System.currentTimeMillis() + 3600_000));
    }

    private String bearer(JWTClaimsSet claims, RSAKey signingKey) throws Exception
    {
        SignedJWT jwt = new SignedJWT(
            new JWSHeader.Builder(JWSAlgorithm.RS256).type(JOSEObjectType.JWT).keyID(signingKey.getKeyID()).build(),
            claims);
        jwt.sign(new RSASSASigner(signingKey));

        return "Bearer " + jwt.serialize();
    }

    private String bearer(JWTClaimsSet claims) throws Exception
    {
        return bearer(claims, this.key);
    }

    @Test
    void validToken() throws Exception
    {
        XWikiUser user = this.authenticator.checkAuth(bearer(claims().build()));

        assertEquals(USER, user.getUserReference());
    }

    @Test
    void scopesAmongOthers() throws Exception
    {
        XWikiUser user =
            this.authenticator.checkAuth(bearer(claims().claim("scp", "other access_as_user more").build()));

        assertEquals(USER, user.getUserReference());
    }

    @Test
    void noIssuerConfigured() throws Exception
    {
        when(this.configuration.getExternalIssuers()).thenReturn(Collections.emptyList());

        assertNull(this.authenticator.checkAuth(bearer(claims().build())));
    }

    @Test
    void notAJWT() throws Exception
    {
        // An access token issued by the wiki's own OpenID Connect Provider.
        assertNull(this.authenticator.checkAuth("Bearer xwiki:XWiki.jdoe/0123456789"));
        assertNull(this.authenticator.checkAuth("Basic amRvZTpwYXNz"));
        assertNull(this.authenticator.checkAuth(null));
    }

    @Test
    void otherIssuer() throws Exception
    {
        assertNull(this.authenticator.checkAuth(bearer(claims().issuer("https://other.example.com").build())));
    }

    @Test
    void wrongAudience() throws Exception
    {
        String token = bearer(claims().audience("someone-else").build());

        assertThrows(Exception.class, () -> this.authenticator.checkAuth(token));
    }

    @Test
    void expired() throws Exception
    {
        String token = bearer(claims().expirationTime(new Date(System.currentTimeMillis() - 3600_000)).build());

        assertThrows(Exception.class, () -> this.authenticator.checkAuth(token));
    }

    @Test
    void missingScope() throws Exception
    {
        // An ID token has the same audience but no scope.
        String token = bearer(claims().claim("scp", null).build());

        assertThrows(IllegalArgumentException.class, () -> this.authenticator.checkAuth(token));
    }

    @Test
    void signedWithAnotherKey() throws Exception
    {
        String token = bearer(claims().build(), new RSAKeyGenerator(2048).keyID("key1").generate());

        assertThrows(Exception.class, () -> this.authenticator.checkAuth(token));
    }

    @Test
    void unknownUser() throws Exception
    {
        String token = bearer(claims().claim("preferred_username", "nobody@example.com").build());

        assertThrows(IllegalArgumentException.class, () -> this.authenticator.checkAuth(token));
    }

    @Test
    void disabledUser() throws Exception
    {
        when(this.userObject.getIntValue(anyString(), anyInt())).thenReturn(0);
        String token = bearer(claims().build());

        assertThrows(IllegalArgumentException.class, () -> this.authenticator.checkAuth(token));
    }

    @Test
    void scopesAsList() throws Exception
    {
        List<String> scopes = Arrays.asList("access_as_user");
        XWikiUser user = this.authenticator.checkAuth(bearer(claims().claim("scp", null).claim("scope", scopes)
            .build()));

        assertEquals(USER, user.getUserReference());
    }
}
