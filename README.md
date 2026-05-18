# CraftsNet Security

A modular authentication and authorization extension for the CraftsNet framework.

![Latest Release on Maven](https://repo.craftsblock.de/api/badge/latest/releases/de/craftsblock/craftsnet/modules/security/bom?color=40c14a&name=CraftsNet%20Security&prefix=v)
![GitHub code size in bytes](https://img.shields.io/github/languages/code-size/CraftsBlock/CraftsNet-Security)
![GitHub](https://img.shields.io/github/license/CraftsBlock/CraftsNet-Security)
![GitHub all releases](https://img.shields.io/github/downloads/CraftsBlock/CraftsNet-Security/total)
![GitHub issues](https://img.shields.io/github/issues-raw/CraftsBlock/CraftsNet-Security)

---

## Features

CraftsNet Security introduces flexible authentication chains, scoped access control, token-based authentication, and extensible persistence drivers
for CraftsNet applications.

* Modular authentication chain system
* Token-based authentication
* Scope-based authorization
* Group-based authorization
* Extensible storage driver architecture
* File and SQL drivers included
    * SQL schema migration system
    * Hot reload support for file-based stores
* Automatic cache revalidation

# Installation

There are currently three modules:

- [common](https://repo.craftsblock.de/#/releases/de/craftsblock/craftsnet/modules/security/common)
    - Addon class: `de.craftsblock.cnet.modules.security.CraftsNetSecurity`
    - Addon name: `CraftsNetSecurity`
- [token](https://repo.craftsblock.de/#/releases/de/craftsblock/craftsnet/modules/security/token)
    - Addon class: `de.craftsblock.cnet.modules.security.token.CraftsNetSecurityToken`
    - Addon name: `CraftsNetSecurityToken`
    - Requires: `common`
- [token-sql](https://repo.craftsblock.de/#/releases/de/craftsblock/craftsnet/modules/security/token-sql)
    - Addon class: `de.craftsblock.cnet.modules.security.token.CraftsNetSecurityTokenSQLDriver`
    - Addon name: `CraftsNetSecurityTokenSQLDriver
    - Requires: `common`, `token`

> [!WARNING]
> You need to depend on the module addon classes that you use to allow proper initialization.
> Use the `depends` field in your addon.json for file addons or the `@Depends` annotation on your addon class for in-app addons. You can use the
`depends` field and the `@Depends` annotation simultaneously.

## Gradle

```groovy
repositories {
    maven {
        name = "craftsblockReleases"
        url = "https://repo.craftsblock.de/releases"
    }
}

dependencies {
    implementation("de.craftsblock.craftsnet.modules.security:<MODULE>:<VERSION>")
}
```

## Maven

```xml

<repositories>
    <repository>
        <id>craftsblock-releases</id>
        <name>CraftsBlock Repositories</name>
        <url>https://repo.craftsblock.de/releases</url>
    </repository>
</repositories>

<dependencies>
<dependency>
    <groupId>de.craftsblock.craftsnet.modules.security</groupId>
    <artifactId>MODULE</artifactId>
    <version>VERSION</version>
</dependency>
</dependencies>
```

### Compatibility

| CraftsNet Version | Compatible |
|-------------------|------------|
| >= 3.7.2          | ✅          |
| 3.7.0 & 3.7.1     | 🧪         |
| < 3.7.0           | ❌          |
