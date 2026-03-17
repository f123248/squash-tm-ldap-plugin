package org.squashtest.tm.plugin.authentication.ldap;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.ldap.core.support.BaseLdapPathContextSource;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.ldap.DefaultSpringSecurityContextSource;
import org.springframework.security.ldap.authentication.BindAuthenticator;
import org.springframework.security.ldap.authentication.LdapAuthenticationProvider;
import org.springframework.security.ldap.search.FilterBasedLdapUserSearch;

import java.util.ArrayList;
import java.util.List;

@AutoConfiguration
@EnableConfigurationProperties(LdapProperties.class)
public class LdapAuthenticationAutoConfiguration {

    private static final Logger log =
            LoggerFactory.getLogger(LdapAuthenticationAutoConfiguration.class);

    private final LdapProperties props;

    public LdapAuthenticationAutoConfiguration(LdapProperties props) {
        this.props = props;
    }

    @Bean
    @ConditionalOnMissingBean(BaseLdapPathContextSource.class)
    public DefaultSpringSecurityContextSource ldapContextSource() {
        log.info("[squash-ldap] Connecting to LDAP at {}", props.getServer().getUrl());

        DefaultSpringSecurityContextSource ctx =
                new DefaultSpringSecurityContextSource(props.getServer().getUrl());

        String managerDn = props.getServer().getManagerDn();
        if (managerDn != null && !managerDn.isBlank()) {
            ctx.setUserDn(managerDn);
            ctx.setPassword(props.getServer().getManagerPassword());
        }

        if (props.getServer().getConnectTimeout() > 0) {
            ctx.setBaseEnvironmentProperties(java.util.Map.of(
                "com.sun.jndi.ldap.connect.timeout",
                String.valueOf(props.getServer().getConnectTimeout())));
        }

        ctx.afterPropertiesSet();
        return ctx;
    }

    @Bean
    public BindAuthenticator ldapBindAuthenticator(
            DefaultSpringSecurityContextSource contextSource) {

        BindAuthenticator auth = new BindAuthenticator(contextSource);
        LdapProperties.User u = props.getUser();

        if (u.getSearchFilter() != null && !u.getSearchFilter().isBlank()) {
            log.info("[squash-ldap] User lookup: searchBase='{}' filter='{}'",
                    u.getSearchBase(), u.getSearchFilter());
            FilterBasedLdapUserSearch search = new FilterBasedLdapUserSearch(
                    u.getSearchBase(), u.getSearchFilter(), contextSource);
            search.setSearchSubtree(u.isSearchSubtree());
            auth.setUserSearch(search);
        }

        if (u.getDnPatterns() != null && !u.getDnPatterns().isBlank()) {
            log.info("[squash-ldap] User lookup: DN-pattern '{}'", u.getDnPatterns());
            List<String> patterns = new ArrayList<>();
            for (String p : u.getDnPatterns().split(",")) {
                String t = p.trim();
                if (!t.isEmpty()) patterns.add(t);
            }
            auth.setUserDnPatterns(patterns.toArray(new String[0]));
        }

        return auth;
    }

    @Bean
    public LdapPostCreateSyncListener ldapPostCreateSyncListener(JdbcTemplate jdbcTemplate) {
        return new LdapPostCreateSyncListener(jdbcTemplate, props.isEnabled());
    }

    @Bean
    public AuthenticationProvider ldapAuthenticationProvider(
            BindAuthenticator bindAuthenticator,
            UserDetailsService userDetailsService,
            JdbcTemplate jdbcTemplate) {

        log.info("[squash-ldap] Registering LdapAuthenticationProvider (enabled={} autoCreateUser={})",
                props.isEnabled(), props.isAutoCreateUser());

        LdapAuthenticationProvider provider = new LdapAuthenticationProvider(bindAuthenticator) {
            @Override
            protected org.springframework.security.core.Authentication createSuccessfulAuthentication(
                    org.springframework.security.authentication.UsernamePasswordAuthenticationToken authentication,
                    org.springframework.security.core.userdetails.UserDetails user) {

                org.springframework.security.core.Authentication base =
                        super.createSuccessfulAuthentication(authentication, user);

                // Fetch synced profile from DB to populate firstName/lastName/email on auto-create
                String login = user.getUsername();
                String firstName = "";
                String lastName  = "";
                String email     = login;

                // If auto-create path: LdapUserDetails carries LDAP attrs directly
                if (user instanceof LdapUserDetails ldapUser) {
                    firstName = ldapUser.getFirstName();
                    lastName  = ldapUser.getLastName();
                    email     = ldapUser.getEmail().isEmpty() ? login : ldapUser.getEmail();
                } else {
                    // Existing user: fetch synced profile from DB
                    try {
                        java.util.List<java.util.Map<String, Object>> rows = jdbcTemplate.queryForList(
                            "SELECT first_name, last_name, email FROM core_user WHERE LOWER(login) = LOWER(?)",
                            login);
                        if (!rows.isEmpty()) {
                            firstName = String.valueOf(rows.get(0).getOrDefault("first_name", ""));
                            lastName  = String.valueOf(rows.get(0).getOrDefault("last_name", ""));
                            email     = String.valueOf(rows.get(0).getOrDefault("email", login));
                        }
                    } catch (Exception ignored) {}
                }

                return new SquashLdapAuthenticationToken(
                        user,
                        base.getCredentials(),
                        base.getAuthorities(),
                        firstName,
                        lastName,
                        email,
                        props.isAutoCreateUser());
            }
        };

        provider.setUserDetailsContextMapper(
                new SquashLdapUserDetailsMapper(
                        props.getUser(),
                        userDetailsService,
                        jdbcTemplate,
                        props.isEnabled(),
                        props.isAutoCreateUser()));

        return provider;
    }
}
