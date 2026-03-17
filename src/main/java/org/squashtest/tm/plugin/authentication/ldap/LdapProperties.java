package org.squashtest.tm.plugin.authentication.ldap;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "authentication.ldap")
public class LdapProperties {

    /** When true, local password login is disabled after first LDAP login */
    private boolean enabled = false;

    /**
     * When true, users that authenticate via LDAP but don't have a Squash TM
     * account will be automatically created on first login.
     * When false (default), login is rejected and admin must create the account first.
     * Docker env var: AUTHENTICATION_LDAP_AUTO_CREATE_USER=true
     */
    private boolean autoCreateUser = false;

    private final Server server = new Server();
    private final User user = new User();

    public boolean isEnabled()               { return enabled; }
    public void setEnabled(boolean v)        { this.enabled = v; }
    public boolean isAutoCreateUser()        { return autoCreateUser; }
    public void setAutoCreateUser(boolean v) { this.autoCreateUser = v; }
    public Server getServer()              { return server; }
    public User getUser()                  { return user; }

    public static class Server {
        private String url = "ldap://localhost:389";
        private String managerDn;
        private String managerPassword;
        private int connectTimeout = 5000;

        public String getUrl()                   { return url; }
        public void setUrl(String v)             { this.url = v; }
        public String getManagerDn()             { return managerDn; }
        public void setManagerDn(String v)       { this.managerDn = v; }
        public String getManagerPassword()       { return managerPassword; }
        public void setManagerPassword(String v) { this.managerPassword = v; }
        public int getConnectTimeout()           { return connectTimeout; }
        public void setConnectTimeout(int v)     { this.connectTimeout = v; }
    }

    public static class User {
        private String searchBase = "";
        private String searchFilter = "(uid={0})";
        private boolean searchSubtree = true;
        private String dnPatterns;
        private String firstNameAttribute = "givenName";
        private String lastNameAttribute = "sn";
        private String emailAttribute = "mail";

        public String getSearchBase()               { return searchBase; }
        public void setSearchBase(String v)         { this.searchBase = v; }
        public String getSearchFilter()             { return searchFilter; }
        public void setSearchFilter(String v)       { this.searchFilter = v; }
        public boolean isSearchSubtree()            { return searchSubtree; }
        public void setSearchSubtree(boolean v)     { this.searchSubtree = v; }
        public String getDnPatterns()               { return dnPatterns; }
        public void setDnPatterns(String v)         { this.dnPatterns = v; }
        public String getFirstNameAttribute()       { return firstNameAttribute; }
        public void setFirstNameAttribute(String v) { this.firstNameAttribute = v; }
        public String getLastNameAttribute()        { return lastNameAttribute; }
        public void setLastNameAttribute(String v)  { this.lastNameAttribute = v; }
        public String getEmailAttribute()           { return emailAttribute; }
        public void setEmailAttribute(String v)     { this.emailAttribute = v; }
    }
}
