package org.squashtest.tm.plugin.authentication.ldap;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;

import java.util.Collection;

/**
 * Minimal UserDetails that carries LDAP attributes (firstName, lastName, email)
 * so they can be passed to SquashLdapAuthenticationToken for auto-create.
 */
public class LdapUserDetails extends User {

    private final String firstName;
    private final String lastName;
    private final String email;

    public LdapUserDetails(
            String username,
            Collection<? extends GrantedAuthority> authorities,
            String firstName,
            String lastName,
            String email) {

        super(username, "", authorities);
        this.firstName = firstName != null ? firstName : "";
        this.lastName  = lastName  != null ? lastName  : "";
        this.email     = email     != null ? email     : "";
    }

    public String getFirstName() { return firstName; }
    public String getLastName()  { return lastName; }
    public String getEmail()     { return email; }
}
