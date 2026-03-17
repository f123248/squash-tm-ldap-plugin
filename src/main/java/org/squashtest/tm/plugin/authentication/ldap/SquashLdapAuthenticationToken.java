package org.squashtest.tm.plugin.authentication.ldap;

import org.squashtest.tm.api.security.authentication.AuthenticationProviderFeatures;
import org.squashtest.tm.api.security.authentication.ExtraAccountInformationAuthentication;
import org.squashtest.tm.api.security.authentication.FeaturesAwareAuthentication;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;

/**
 * Custom LDAP authentication token that implements:
 * - FeaturesAwareAuthentication: tells Squash TM this provider's features
 * - ExtraAccountInformationAuthentication: provides firstName/lastName/email
 *   so Squash TM's AuthenticatedMissingUserCreator can populate the new user
 */
public class SquashLdapAuthenticationToken extends AbstractAuthenticationToken
        implements FeaturesAwareAuthentication, ExtraAccountInformationAuthentication {

    private final UserDetails principal;
    private final Object credentials;
    private final String firstName;
    private final String lastName;
    private final String email;
    private final AuthenticationProviderFeatures features;

    public SquashLdapAuthenticationToken(
            UserDetails principal,
            Object credentials,
            Collection<? extends GrantedAuthority> authorities,
            String firstName,
            String lastName,
            String email,
            boolean shouldCreateMissingUser) {

        super(authorities);
        this.principal   = principal;
        this.credentials = credentials;
        this.firstName   = firstName != null ? firstName : "";
        this.lastName    = lastName  != null ? lastName  : "";
        this.email       = email     != null ? email     : "";
        this.features    = new LdapProviderFeatures(shouldCreateMissingUser);
        setAuthenticated(true);
    }

    @Override public Object getPrincipal()   { return principal; }
    @Override public Object getCredentials() { return credentials; }

    @Override
    public AuthenticationProviderFeatures getFeatures() { return features; }

    @Override public String getFirstName() { return firstName; }
    @Override public String getLastName()  { return lastName; }
    @Override public String getEmail()     { return email; }

    // ── Inner feature class ──────────────────────────────────────────────

    private static class LdapProviderFeatures implements AuthenticationProviderFeatures {

        private final boolean createMissingUser;

        LdapProviderFeatures(boolean createMissingUser) {
            this.createMissingUser = createMissingUser;
        }

        @Override public boolean isManagedPassword()       { return true; }
        @Override public String  getProviderName()         { return "ldap"; }
        @Override public boolean shouldCreateMissingUser() { return createMissingUser; }
    }
}
