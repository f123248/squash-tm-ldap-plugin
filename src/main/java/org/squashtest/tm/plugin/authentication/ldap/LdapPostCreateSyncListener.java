package org.squashtest.tm.plugin.authentication.ldap;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.ApplicationListener;
import org.springframework.core.Ordered;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.authentication.event.AuthenticationSuccessEvent;

/**
 * Listens to AuthenticationSuccessEvent AFTER Squash TM's AuthenticatedMissingUserCreator
 * (which runs at Integer.MIN_VALUE + 1) to sync profile for newly auto-created accounts.
 *
 * Order 0 ensures we run after the user has already been created in DB.
 */
public class LdapPostCreateSyncListener
        implements ApplicationListener<AuthenticationSuccessEvent>, Ordered {

    private static final Logger log = LoggerFactory.getLogger(LdapPostCreateSyncListener.class);

    private final JdbcTemplate jdbcTemplate;
    private final boolean enabled;

    public LdapPostCreateSyncListener(JdbcTemplate jdbcTemplate, boolean enabled) {
        this.jdbcTemplate = jdbcTemplate;
        this.enabled = enabled;
    }

    @Override
    public int getOrder() {
        return 0; // run after AuthenticatedMissingUserCreator (Integer.MIN_VALUE + 1)
    }

    @Override
    public void onApplicationEvent(AuthenticationSuccessEvent event) {
        if (!(event.getAuthentication() instanceof SquashLdapAuthenticationToken token)) return;
        if (!(token.getPrincipal() instanceof LdapUserDetails ldapUser)) return;

        // Only needed for auto-create path (LdapUserDetails = fallback, not full Squash user)
        String login     = ldapUser.getUsername();
        String firstName = ldapUser.getFirstName();
        String lastName  = ldapUser.getLastName();
        String email     = ldapUser.getEmail();

        log.info("[squash-ldap] Post-create sync for '{}'", login);

        try {
            int updated = jdbcTemplate.update(
                "UPDATE core_user SET " +
                "  first_name       = CASE WHEN ? <> '' THEN ? ELSE first_name END, " +
                "  last_name        = CASE WHEN ? <> '' THEN ? ELSE last_name  END, " +
                "  email            = CASE WHEN ? <> '' THEN ? ELSE email      END, " +
                "  created_by       = 'ldap-plugin', " +
                "  last_modified_on = NOW(), last_modified_by = 'ldap-plugin' " +
                "WHERE LOWER(login) = LOWER(?)",
                firstName, firstName,
                lastName,  lastName,
                email,     email,
                login);
            if (updated > 0)
                log.info("[squash-ldap] Post-create profile synced for '{}'", login);
            else
                log.warn("[squash-ldap] Post-create: core_user not found for '{}' — user may not have been created", login);
        } catch (Exception e) {
            log.warn("[squash-ldap] Post-create sync failed for '{}': {}", login, e.getMessage());
        }

        // Invalidate local password in auth_user
        if (enabled) {
            try {
                jdbcTemplate.update(
                    "UPDATE auth_user SET password = ? WHERE LOWER(login) = LOWER(?)",
                    generateRandomBcrypt(), login);
                log.info("[squash-ldap] Post-create: local password invalidated for '{}'", login);
            } catch (Exception e) {
                log.warn("[squash-ldap] Post-create: password invalidation failed for '{}': {}", login, e.getMessage());
            }
        }
    }

    private String generateRandomBcrypt() {
        String random = java.util.UUID.randomUUID().toString() +
                        java.util.UUID.randomUUID().toString();
        return "{bcrypt}" + new org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder().encode(random);
    }
}
