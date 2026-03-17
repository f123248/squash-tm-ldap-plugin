package org.squashtest.tm.plugin.authentication.ldap;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.ldap.core.DirContextAdapter;
import org.springframework.ldap.core.DirContextOperations;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.ldap.userdetails.LdapUserDetailsMapper;

import java.util.Collection;
import java.util.Collections;
import java.util.List;

/**
 * After LDAP bind succeeds:
 * 1. Fetch firstName/lastName/email from LDAP
 * 2. Case-insensitive lookup in Squash TM DB
 * 3. Found → sync profile + (if enabled) invalidate local password → load full UserDetails
 * 4. Not found + autoCreateUser=true → return minimal UserDetails so Squash TM auto-creates account
 * 5. Not found + autoCreateUser=false → reject login
 */
public class SquashLdapUserDetailsMapper extends LdapUserDetailsMapper {

    private static final Logger log = LoggerFactory.getLogger(SquashLdapUserDetailsMapper.class);

    private final LdapProperties.User userProps;
    private final UserDetailsService squashUserDetailsService;
    private final JdbcTemplate jdbcTemplate;
    private final boolean enabled;
    private final boolean autoCreateUser;

    public SquashLdapUserDetailsMapper(
            LdapProperties.User userProps,
            UserDetailsService squashUserDetailsService,
            JdbcTemplate jdbcTemplate,
            boolean enabled,
            boolean autoCreateUser) {
        this.userProps = userProps;
        this.squashUserDetailsService = squashUserDetailsService;
        this.jdbcTemplate = jdbcTemplate;
        this.enabled = enabled;
        this.autoCreateUser = autoCreateUser;
    }

    @Override
    public UserDetails mapUserFromContext(
            DirContextOperations ctx,
            String username,
            Collection<? extends GrantedAuthority> authorities) {

        log.info("[squash-ldap] LDAP bind success for '{}'", username);

        String firstName = getAttr(ctx, userProps.getFirstNameAttribute());
        String lastName  = getAttr(ctx, userProps.getLastNameAttribute());
        String email     = getAttr(ctx, userProps.getEmailAttribute());

        String resolvedLogin = resolveLoginCaseInsensitive(username);

        if (resolvedLogin == null) {
            if (autoCreateUser) {
                // Return minimal UserDetails carrying LDAP attrs — Squash TM's
                // AuthenticatedMissingUserCreator will auto-create the account
                // after AuthenticationSuccessEvent
                log.info("[squash-ldap] User '{}' not in DB, will be auto-created by Squash TM", username);
                return buildFallback(username, firstName, lastName, email);
            } else {
                log.warn("[squash-ldap] User '{}' not found in DB. Admin must create the account first.", username);
                throw new UsernameNotFoundException(
                    "User '" + username + "' authenticated via LDAP but has no Squash TM account. " +
                    "Please contact your administrator.");
            }
        }

        log.info("[squash-ldap] DB match: '{}' → '{}'", username, resolvedLogin);

        syncUserProfile(resolvedLogin, firstName, lastName, email);

        try {
            UserDetails details = squashUserDetailsService.loadUserByUsername(resolvedLogin);
            log.info("[squash-ldap] Loaded full UserDetails for '{}', authorities={}",
                    resolvedLogin, details.getAuthorities());
            return details;
        } catch (Exception e) {
            log.error("[squash-ldap] Failed to load UserDetails for '{}': {}", resolvedLogin, e.getMessage());
            throw new UsernameNotFoundException(
                "Failed to load Squash TM user '" + resolvedLogin + "'", e);
        }
    }

    @Override
    public void mapUserToContext(UserDetails user, DirContextAdapter ctx) {
        throw new UnsupportedOperationException("Read-only.");
    }

    private String resolveLoginCaseInsensitive(String username) {
        if (jdbcTemplate == null) return null;
        try {
            List<String> results = jdbcTemplate.queryForList(
                "SELECT login FROM core_user WHERE LOWER(login) = LOWER(?)",
                String.class, username);
            return results.isEmpty() ? null : results.get(0);
        } catch (Exception e) {
            log.error("[squash-ldap] DB lookup failed for '{}': {}", username, e.getMessage());
            return null;
        }
    }

    private void syncUserProfile(String login, String firstName, String lastName, String email) {
        if (jdbcTemplate == null) return;
        try {
            // Update profile fields in core_user (no password column here)
            int updated = jdbcTemplate.update(
                "UPDATE core_user SET " +
                "  first_name = CASE WHEN ? <> '' THEN ? ELSE first_name END, " +
                "  last_name  = CASE WHEN ? <> '' THEN ? ELSE last_name  END, " +
                "  email      = CASE WHEN ? <> '' THEN ? ELSE email      END, " +
                "  created_by = CASE WHEN (created_by IS NULL OR created_by = '') THEN 'ldap-plugin' ELSE created_by END, " +
                "  last_modified_on = NOW(), last_modified_by = 'ldap-plugin' " +
                "WHERE LOWER(login) = LOWER(?)",
                firstName, firstName,
                lastName,  lastName,
                email,     email,
                login);
            if (updated > 0)
                log.info("[squash-ldap] Synced profile for '{}'", login);
        } catch (Exception e) {
            log.warn("[squash-ldap] Profile sync failed for '{}': {}", login, e.getMessage());
        }

        // Invalidate local password in AUTH_USER (Spring Security table)
        if (enabled) {
            try {
                int updated = jdbcTemplate.update(
                    "UPDATE auth_user SET password = ? WHERE LOWER(login) = LOWER(?)",
                    generateRandomBcrypt(), login);
                if (updated > 0)
                    log.info("[squash-ldap] Local password invalidated for '{}'", login);
                else
                    log.warn("[squash-ldap] auth_user not found for '{}', password not invalidated", login);
            } catch (Exception e) {
                log.warn("[squash-ldap] Password invalidation failed for '{}': {}", login, e.getMessage());
            }
        }
    }

    private String generateRandomBcrypt() {
        // Generate a random bcrypt hash that nobody can guess or reverse
        String random = java.util.UUID.randomUUID().toString() +
                        java.util.UUID.randomUUID().toString();
        return "{bcrypt}" + org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder.class
                .cast(new org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder())
                .encode(random);
    }

    private LdapUserDetails buildFallback(String username, String firstName, String lastName, String email) {
        return new LdapUserDetails(
                username,
                Collections.singletonList(new SimpleGrantedAuthority("ROLE_USER")),
                firstName,
                lastName,
                email);
    }

    private String getAttr(DirContextOperations ctx, String attrName) {
        if (attrName == null || attrName.isBlank()) return "";
        try {
            String val = ctx.getStringAttribute(attrName);
            return val != null ? val : "";
        } catch (Exception e) {
            return "";
        }
    }
}
