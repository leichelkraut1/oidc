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

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.regex.Pattern;

import javax.inject.Singleton;

import org.apache.commons.lang3.StringUtils;
import org.xwiki.component.annotation.Component;
import org.xwiki.contrib.oidc.internal.OIDCConfiguration;
import org.xwiki.contrib.usercommon.formatter.UserFormatterFactory;

/**
 * Various OpenID Connect authenticator configurations.
 * 
 * @version $Id$
 * @since 2.21.0
 */
@Component(roles = TokenAuthenticatorConfiguration.class)
@Singleton
public class TokenAuthenticatorConfiguration extends OIDCConfiguration
{
    /**
     * The prefix used for Token Authenticator configuration properties.
     */
    public static final String PREFIX_PROP = OIDCConfiguration.PREFIX_PROP + "token.";

    /**
     * The name of the property containing the authenticator to fallback to.
     */
    public static final String PROP_AUTHENTICATOR = PREFIX_PROP + "authenticator";

    /**
     * The former name of the property containing the authenticator to fallback to.
     */
    private static final String PROP_AUTHENTICATOR_LEGACY = OIDCConfiguration.PREFIX_PROP + "provider.authenticator";

    /**
     * The prefix of the properties about access tokens issued by external providers.
     *
     * @since 2.31.0
     */
    public static final String PREFIX_PROP_EXTERNAL = PREFIX_PROP + "external.";

    /**
     * The issuers (as in the tokens' "iss" claim) whose access tokens are accepted.
     *
     * @since 2.31.0
     */
    public static final String PROP_EXTERNAL_ISSUERS = PREFIX_PROP_EXTERNAL + "issuers";

    /**
     * The accepted audiences (the tokens' "aud" claim).
     *
     * @since 2.31.0
     */
    public static final String PROP_EXTERNAL_AUDIENCES = PREFIX_PROP_EXTERNAL + "audiences";

    /**
     * The scopes an access token must have (in its "scope" or "scp" claim).
     *
     * @since 2.31.0
     */
    public static final String PROP_EXTERNAL_SCOPES = PREFIX_PROP_EXTERNAL + "scopes";

    /**
     * The format of the subject that identifies the user of an access token.
     *
     * @since 2.31.0
     */
    public static final String PROP_EXTERNAL_SUBJECTFORMATER = PREFIX_PROP_EXTERNAL + "subjectFormater";

    // The OpenID Connect Authenticator's properties, so a token maps to the same user as the browser sign-in.
    private static final String PROP_USER_SUBJECTFORMATER = "oidc.user.subjectFormater";

    private static final String PROP_USER_SUBJECTFORBIDDENPATTERN = "oidc.user.subjectForbiddenPattern";

    private static final String PROP_USER_SUBJECTFORBIDDENREPLACEMENT = "oidc.user.subjectForbiddenReplacement";

    private static final String DEFAULT_USER_SUBJECTFORMATER = "${oidc.user.subject}";

    /**
     * @return the authenticator to fallback to
     */
    public String getAuthenticator()
    {
        String authenticator = getProperty(PROP_AUTHENTICATOR, (String) null);

        if (authenticator == null) {
            // Try the legacy property for backward compatibility.
            authenticator = getProperty(PROP_AUTHENTICATOR_LEGACY, (String) null);
        }

        return authenticator;
    }

    /**
     * @return the issuers whose access tokens are accepted, empty to accept none
     * @since 2.31.0
     */
    public List<String> getExternalIssuers()
    {
        return getList(PROP_EXTERNAL_ISSUERS);
    }

    /**
     * @return the accepted values of the access tokens' "aud" claim; a token matches if it has one of them
     * @since 2.31.0
     */
    public List<String> getExternalAudiences()
    {
        return getList(PROP_EXTERNAL_AUDIENCES);
    }

    /**
     * @return the scopes an access token must all have, empty to require none
     * @since 2.31.0
     */
    public List<String> getExternalScopes()
    {
        return getList(PROP_EXTERNAL_SCOPES);
    }

    /**
     * @return the format of the subject that identifies the user of an access token, by default the one the OpenID
     *         Connect Authenticator uses ({@code oidc.user.subjectFormater})
     * @since 2.31.0
     */
    public String getExternalSubjectFormater()
    {
        String format = getProperty(PROP_EXTERNAL_SUBJECTFORMATER, (String) null);
        if (StringUtils.isEmpty(format)) {
            format = getProperty(PROP_USER_SUBJECTFORMATER, (String) null);
        }

        return StringUtils.isEmpty(format) ? DEFAULT_USER_SUBJECTFORMATER : format;
    }

    /**
     * @return the characters removed from the subject, like the OpenID Connect Authenticator does
     * @since 2.31.0
     */
    public Pattern getSubjectForbiddenPattern()
    {
        String regex = getProperty(PROP_USER_SUBJECTFORBIDDENPATTERN, (String) null);

        return StringUtils.isEmpty(regex) ? UserFormatterFactory.DEFAULT_FORBIDDEN_PATTERN : Pattern.compile(regex);
    }

    /**
     * @return the replacement of the forbidden characters in the subject
     * @since 2.31.0
     */
    public String getSubjectForbiddenReplacement()
    {
        String replacement = getProperty(PROP_USER_SUBJECTFORBIDDENREPLACEMENT, (String) null);

        return StringUtils.isEmpty(replacement) ? UserFormatterFactory.DEFAULT_FORBIDDEN_REPLACEMENT : replacement;
    }

    private List<String> getList(String key)
    {
        List<?> values = getProperty(key, List.class);
        if (values == null) {
            return Collections.emptyList();
        }

        List<String> list = new ArrayList<>();
        for (Object value : values) {
            String trimmed = StringUtils.trimToNull(String.valueOf(value));
            if (trimmed != null) {
                list.add(trimmed);
            }
        }

        return list;
    }
}
