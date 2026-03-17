# Squash TM 13 — Community LDAP / Active Directory Plugin

A community-built LDAP/AD authentication plugin for **Squash TM 13.x**, rewritten from scratch for Spring Boot 3 / Spring Security 6 / Jakarta EE.

> The original [amtgroup/squash-tm-plugins](https://github.com/amtgroup/squash-tm-plugins) targets Squash TM 4.18.x (Spring Boot 1.x / `javax.*`) and is incompatible with Squash TM 10+.

---

## Features

- 🔐 LDAP / Active Directory authentication (pass-through, passwords never stored)
- 🔄 Auto-sync `firstName`, `lastName`, `email` from LDAP on every login
- 🔒 Optional: invalidate local password after first LDAP login
- 👤 Optional: auto-create Squash TM account on first LDAP login
- 🔍 Case-insensitive username matching between LDAP and Squash TM DB
- 👑 `admin` account is always exempt from any LDAP restrictions

---

## Requirements

- Squash TM 13.x (`squashtest/squash:13.x`)
- Java 17+
- Maven 3.9+ (for building)

---

## Build

```bash
# Build with Maven (requires Java 21)
mvn -B package -DskipTests

# With Docker (no local JDK required)
docker run --rm -v "$(pwd)":/build -w /build \
  maven:3.9-eclipse-temurin-21 mvn -B package -DskipTests

# Output JAR
ls target/authentication.ldap.ad-1.0.0.jar
```

---

## Installation

```bash
# First time: extract existing plugins from the container
mkdir -p /app/squash/plugins
docker cp squash-tm:/opt/squash-tm/plugins/. /app/squash/plugins/

# Copy the plugin JAR
cp target/authentication.ldap.ad-2.0.0.jar /app/squash/plugins/
```

Mount the plugins directory and configure environment variables in `docker-compose.yml`, then restart Squash TM.

---

## Configuration

### Connection Settings (Required)

| Environment Variable | Default | Description |
|---|---|---|
| `AUTHENTICATION_LDAP_SERVER_URL` | `ldap://localhost:389` | LDAP / AD server URL |
| `AUTHENTICATION_LDAP_SERVER_MANAGERDN` | — | Manager bind DN (e.g. `svc-squash@corp.com`) |
| `AUTHENTICATION_LDAP_SERVER_MANAGERPASSWORD` | — | Manager bind password |
| `AUTHENTICATION_LDAP_SERVER_CONNECTTIMEOUT` | `5000` | Connection timeout in milliseconds |

### User Search Settings (Required)

| Environment Variable | Default | Description |
|---|---|---|
| `AUTHENTICATION_LDAP_USER_SEARCHBASE` | `""` | Base DN for user search |
| `AUTHENTICATION_LDAP_USER_SEARCHFILTER` | `(uid={0})` | LDAP filter — `{0}` is replaced by the username |
| `AUTHENTICATION_LDAP_USER_SEARCHSUBTREE` | `true` | Search sub-trees |
| `AUTHENTICATION_LDAP_USER_DNPATTERNS` | — | Static DN pattern (alternative to filter-based search) |

### Attribute Mapping (Optional)

| Environment Variable | Default | Description |
|---|---|---|
| `AUTHENTICATION_LDAP_USER_FIRSTNAMEATTRIBUTE` | `givenName` | LDAP attribute for first name |
| `AUTHENTICATION_LDAP_USER_LASTNAMEATTRIBUTE` | `sn` | LDAP attribute for last name |
| `AUTHENTICATION_LDAP_USER_EMAILATTRIBUTE` | `mail` | LDAP attribute for email |

### Feature Flags (Optional)

| Environment Variable | Default | Description |
|---|---|---|
| `AUTHENTICATION_LDAP_ENABLED` | `false` | When `true`, invalidates the local DB password after first LDAP login, preventing local password login for all accounts (except `admin`) |
| `AUTHENTICATION_LDAP_AUTO_CREATE_USER` | `false` | When `true`, automatically creates a Squash TM account on first LDAP login. When `false`, login is rejected if the account does not exist — admin must create it first |

---

## docker-compose.yml Example

```yaml
services:
  squash-tm-pg:
    image: postgres:17
    restart: always
    environment:
      POSTGRES_DB: squashtm
      POSTGRES_USER: squashtm
      POSTGRES_PASSWORD: your_db_password
    volumes:
      - /app/squash/pg-data:/var/lib/postgresql/data

  squash-tm:
    image: squashtest/squash:13.0.1
    restart: always
    depends_on:
      - squash-tm-pg
    environment:
      SPRING_PROFILES_ACTIVE: postgresql
      SPRING_DATASOURCE_URL: jdbc:postgresql://squash-tm-pg:5432/squashtm
      SPRING_DATASOURCE_USERNAME: squashtm
      SPRING_DATASOURCE_PASSWORD: your_db_password

      # ── LDAP / AD ────────────────────────────────────────────────────────
      AUTHENTICATION_LDAP_SERVER_URL: "ldap://your-ad-server:3268"
      AUTHENTICATION_LDAP_SERVER_MANAGERDN: "svc-squash@corp.example.com"
      AUTHENTICATION_LDAP_SERVER_MANAGERPASSWORD: "your_service_account_password"
      AUTHENTICATION_LDAP_USER_SEARCHBASE: "DC=corp,DC=example,DC=com"
      AUTHENTICATION_LDAP_USER_SEARCHFILTER: "(userPrincipalName={0})"
      AUTHENTICATION_LDAP_USER_SEARCHSUBTREE: "true"

      # ── Feature flags ────────────────────────────────────────────────────
      AUTHENTICATION_LDAP_ENABLED: "true"
      AUTHENTICATION_LDAP_AUTO_CREATE_USER: "true"

    volumes:
      - /app/squash/logs:/opt/squash-tm/logs
      - /app/squash/plugins:/opt/squash-tm/plugins
```

---

## How It Works

```
User submits credentials
        ↓
LDAP / AD validates password
        ↓
Plugin queries Squash TM DB (case-insensitive)
        ↓
    ┌───────────────────────────────────────────┐
    │ Account found?                            │
    ├───────────────────────────────────────────┤
    │ YES → Sync firstName / lastName / email   │
    │       ENABLED=true: invalidate local      │
    │       DB password                         │
    │       Load full UserDetails               │
    │       (with all ACL & permissions)        │
    ├───────────────────────────────────────────┤
    │ NO  → AUTO_CREATE_USER=true:              │
    │         Auto-create account               │
    │         (no project permissions yet)      │
    │       AUTO_CREATE_USER=false:             │
    │         Reject login                      │
    └───────────────────────────────────────────┘
```

**Notes:**
- Passwords are never stored — LDAP validates credentials on every login
- `admin` account is always exempt and can log in with its local password
- New auto-created accounts have no project permissions — an admin must assign them

---

## Active Directory Tips

Global Catalog (port 3268, multi-domain):
```yaml
AUTHENTICATION_LDAP_SERVER_URL: "ldap://dc.corp.example.com:3268"
AUTHENTICATION_LDAP_USER_SEARCHFILTER: "(userPrincipalName={0})"
```

Short username (`sAMAccountName`):
```yaml
AUTHENTICATION_LDAP_USER_SEARCHFILTER: "(sAMAccountName={0})"
```

Restrict to a specific AD group:
```yaml
AUTHENTICATION_LDAP_USER_SEARCHFILTER: "(&(userPrincipalName={0})(memberOf=CN=squash-users,OU=Groups,DC=corp,DC=example,DC=com))"
```

---

## Verify Installation

```bash
docker logs squash-tm 2>&1 | grep "\[squash-ldap\]"
```

Expected:
```
[squash-ldap] Connecting to LDAP at ldap://your-ad-server:3268
[squash-ldap] User lookup: searchBase='DC=...' filter='(userPrincipalName={0})'
[squash-ldap] Registering LdapAuthenticationProvider (enabled=true autoCreateUser=true)
```

---

## License

Apache License 2.0 — see [LICENSE](LICENSE)
