SSOwat
======

A simple LDAP SSO for NGINX, written in Lua.

<a href="https://translate.yunohost.org/engage/yunohost/?utm_source=widget">
<img src="https://translate.yunohost.org/widgets/yunohost/-/287x66-white.png" alt="Translation status" />
</a>

Issues
------

- [Please report issues to the YunoHost bugtracker](https://github.com/YunoHost/issues).

Requirements
------------

- `nginx-extras` from Debian wheezy-backports
- `lua-json`
- `lua-ldap`
- `lua-filesystem`
- `lua-socket`
- `lua-rex-pcre`

**OR**

- "OpenResty" flavored NGINX: https://openresty.org/
- `lua-ldap`
- `lua-filesystem`
- `lua-socket`
- `lua-rex-pcre`

Installation
------------

* Fetch the repository

```bash
git clone https://github.com/YunoHost/SSOwat /etc/ssowat
```


NGINX configuration
-------------------

* Add SSOwat's NGINX configuration (`http{}` scope)

```bash
nano /etc/nginx/conf.d/ssowat.conf
```

```nginx

lua_shared_dict cache 10m;
init_by_lua_file   /etc/ssowat/init.lua;
access_by_lua_file /etc/ssowat/access.lua;

```

You can also put the `access_by_lua_file` directive in a `server{}` scope if you want to protect only a vhost.


SSOwat configuration
--------------------

```
mv /etc/ssowat/conf.json.example /etc/ssowat/conf.json
nano /etc/ssowat/conf.json
```

If you use YunoHost, you may want to edit the `/etc/ssowat/conf.json.persistent` file, since the `/etc/ssowat/conf.json` will often be overwritten.

## Available parameters

Only the `portal_domain` SSOwat configuration parameters is required, but it is recommended to know the others to fully understand what you can do with it.

---------------

### portal_domain

Domain of the authentication portal. It has to be a domain, IP addresses will not work with SSOwat (**Required**).

---------------

### portal_path

URI of the authentication portal (**default**: `/ssowat/`). This path **must** end with “`/`”.

---------------

### portal_port

Web port of the authentication portal (**default**: `443` for `https`, `80` for `http`).

---------------

### portal_scheme

Whether authentication should use secure connection or not (**default**: `https`).

---------------

### domains

List of handled domains (**default**: similar to `portal_domain`).

---------------

### ldap_host

LDAP server hostname (**default**: `localhost`).

---------------

### ldap_group

LDAP group to search in (**default**: `ou=users,dc=yunohost,dc=org`).

---------------

### ldap_identifier

LDAP user identifier (**default**: `uid`).

---------------

### ldap_attributes

User's attributes to fetch from LDAP (**default**: `["uid", "givenname", "sn", "cn", "homedirectory", "mail", "maildrop"]`).

---------------

### ldap_enforce_crypt

Let SSOwat re-encrypt weakly-encrypted LDAP passwords into the safer sha-512 (crypt) (**default**: `true`).

---------------

### allow_mail_authentication

Whether users can authenticate with their mail address (**default**: `true`).

---------------

### login_arg

URI argument to use for cross-domain authentication (**default**: `sso_login`).

---------------

### additional_headers

Array of additionnal HTTP headers to set once user is authenticated (**default**: `{ "Remote-User": "uid" }`).

---------------

### session_timeout

The session expiracy time limit in seconds, since the last connection (**default**: `86400` / one day).

---------------

### session_max_timeout

The session expiracy time limit in seconds (**default**: `604800` / one week).

---------------

### redirected_urls

Array of URLs and/or URIs to redirect and their redirect URI/URL (**example**: `{ "/": "example.org/subpath" }`).

---------------

### redirected_regex

Array of regular expressions to be matched against URLs **and** URIs and their redirect URI/URL (**example**: `{ "example.org/megusta$": "example.org/subpath" }`).

---------------

### default_language

Language code used by default in views (**default**: `en`).

---------------

### permissions

The list of permissions depicted as follows:

```json
"myapp.main": {
    "auth_header": true,
    "label": "MyApp",
    "public": true,
    "show_tile": true,
    "uris": [
        "example.tld/myapp"
    ],
    "users": [
        "JaneDoe",
        "JohnDoe"
    ]
},
"myapp.admin": {
    "auth_header": true,
    "label": "MyApp (admin)",
    "public": false,
    "show_tile": false,
    "uris": [
        "example.tld/myapp/admin"
    ],
    "users": [
        "JaneDoe"
    ]
},
"myapp.api": {
    "auth_header": false,
    "label": "MyApp (api)",
    "public": true,
    "show_tile": false,
    "uris": [
        "re:domain%.tld/%.well%-known/.*"
    ],
    "users": []
}
```

#### auth_header

Does the SSO add an authentication header that allows certain apps to connect automatically? (**True by default**)

#### label

A user-friendly name displayed in the portal and in the administration panel to manage permission. (**By convention it is of the form: Name of the app (specificity of this permission)**)

#### public

Can a person who is not connected to the SSO have access to this authorization?

#### show_tile

Display or not the tile in the user portal.

#### uris

A list of url attatched to this permission, a regex url start with `re:`.

#### users

A list of users which is allowed to access to this permission. If `public`.
