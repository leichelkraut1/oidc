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

import java.net.URI;
import java.util.HashMap;
import java.util.Map;

import javax.inject.Inject;
import javax.inject.Singleton;

import org.slf4j.Logger;
import org.xwiki.component.annotation.Component;
import org.xwiki.contrib.oidc.auth.store.OIDCUserStore;
import org.xwiki.contrib.usercommon.formatter.UserFormatter;
import org.xwiki.contrib.usercommon.formatter.UserFormatterFactory;
import org.xwiki.model.reference.LocalDocumentReference;

import com.nimbusds.jwt.JWTClaimsSet;
import com.xpn.xwiki.doc.XWikiDocument;
import com.xpn.xwiki.objects.BaseObject;
import com.xpn.xwiki.user.api.XWikiUser;

/**
 * Authenticates a request carrying an access token issued by an external OAuth2/OpenID Connect provider (Keycloak,
 * Microsoft Entra ID, Okta...), for example an MCP client that signed in with the organization's identity provider.
 * The token (see {@link ExternalTokenValidator}) is mapped to the wiki user that the OpenID Connect Authenticator
 * linked to the same issuer and subject, so the caller acts as the same user as in the browser. No user is created:
 * someone who never signed in through the browser is not authenticated.
 *
 * @version $Id$
 * @since 2.31.0
 */
@Component(roles = ExternalTokenAuthenticator.class)
@Singleton
public class ExternalTokenAuthenticator
{
    private static final LocalDocumentReference USER_CLASS = new LocalDocumentReference("XWiki", "XWikiUsers");

    private static final String USER_ACTIVE = "active";

    private static final String PREFIX_USER = "oidc.user.";

    @Inject
    private ExternalTokenValidator validator;

    @Inject
    private TokenAuthenticatorConfiguration configuration;

    @Inject
    private OIDCUserStore userStore;

    @Inject
    private UserFormatterFactory formatterFactory;

    @Inject
    private Logger logger;

    /**
     * @param authorization the value of the HTTP Authorization header
     * @return the authenticated user, or {@code null} when the header does not carry an access token of a configured
     *         external issuer
     * @throws Exception when the token is from a configured issuer but is not valid or does not match an active user
     */
    public XWikiUser checkAuth(String authorization) throws Exception
    {
        JWTClaimsSet claims = this.validator.validate(authorization);
        if (claims == null) {
            return null;
        }

        String issuer = claims.getIssuer();
        String subject = formatSubject(issuer, claims);
        XWikiDocument userDocument = this.userStore.searchDocument(issuer, subject);
        if (userDocument == null) {
            throw new IllegalArgumentException(
                String.format("No user is linked to issuer [%s] and subject [%s]", issuer, subject));
        }

        BaseObject userObject = userDocument.getXObject(USER_CLASS);
        if (userObject == null || userObject.getIntValue(USER_ACTIVE, 1) == 0) {
            throw new IllegalArgumentException(
                String.format("The user [%s] is disabled", userDocument.getDocumentReference()));
        }

        return new XWikiUser(userDocument.getDocumentReference());
    }

    private String formatSubject(String issuer, JWTClaimsSet claims)
    {
        // The variables the OpenID Connect Authenticator offers for the same claims, so the same format applies.
        Map<String, String> variables = new HashMap<>();
        addClaims(PREFIX_USER, claims.toJSONObject(), variables);
        addClaims("oidc.idtoken.", claims.toJSONObject(), variables);
        variables.put("oidc.user.subject", claims.getSubject());
        Object preferredUsername = claims.getClaim("preferred_username");
        variables.put("oidc.user.preferredUsername",
            preferredUsername != null ? preferredUsername.toString() : claims.getSubject());
        Object mail = claims.getClaim("email");
        variables.put("oidc.user.mail", mail != null ? mail.toString() : "");
        variables.put("oidc.issuer", issuer);
        try {
            URI issuerURI = new URI(issuer);
            variables.put("oidc.issuer.host", issuerURI.getHost());
            variables.put("oidc.issuer.path", issuerURI.getPath());
            variables.put("oidc.issuer.scheme", issuerURI.getScheme());
            variables.put("oidc.issuer.port", String.valueOf(issuerURI.getPort()));
        } catch (Exception e) {
            this.logger.debug("Issuer [{}] is not a valid URI", issuer, e);
        }

        UserFormatter formatter = this.formatterFactory.create(variables,
            this.configuration.getSubjectForbiddenPattern(), this.configuration.getSubjectForbiddenReplacement());

        return formatter.format(this.configuration.getExternalSubjectFormater());
    }

    @SuppressWarnings("unchecked")
    private void addClaims(String prefix, Map<String, ?> json, Map<String, String> variables)
    {
        for (Map.Entry<String, ?> entry : json.entrySet()) {
            if (entry.getValue() instanceof Map) {
                addClaims(prefix + entry.getKey() + '.', (Map<String, ?>) entry.getValue(), variables);
            } else if (entry.getValue() != null) {
                variables.put(prefix + entry.getKey(), entry.getValue().toString());
            }
        }
    }
}
