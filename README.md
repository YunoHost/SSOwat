SSOwat
======

A simple LDAP SSO for nginx, written in Lua

<a href="https://translate.yunohost.org/engage/yunohost/?utm_source=widget">
<img src="https://translate.yunohost.org/widgets/yunohost/-/287x66-white.png" alt="Translation status" />
</a>

Issues
------

- [Please report issues on YunoHost bugtracker](https://dev.yunohost.org/projects/yunohost/issues) (no registration needed).

Requirements
------------

- Nginx-extras from Debian wheezy-backports
- lua-json
- lua-ldap

**OR**

- Nginx "Openresty" flavored : http://openresty.org/
- lua-ldap

Installation
------------

* Fetch the repository

```bash
git clone https://github.com/Kloadut/SSOwat /etc/ssowat
```


Nginx configuration
-------------------

* Add SSOwat's Nginx configuration (`http{}` scope)

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

These are the SSOwat's configuration parameters. Only the first one is required, but it is recommended to know the others to fully understand what you can do with SSOwat.

#### portal_domain

Domain of the authentication portal. It has to be a domain, IP addresses will not work with SSOwat (**Required**)

#### portal_path

URI of the authentication portal (**default**: `/ssowat`)

#### portal_port

Web port of the authentication portal (**default**: `443`)

#### portal_scheme

Whether authentication should use secure connection or not (**default**: `https`)

#### domains

List of handle domains (**default**: similar to `portal_domain`)

#### ldap_host

LDAP server hostname (**default**: `localhost`)

#### ldap_group

LDAP group to search in (**default**: `ou=users,dc=yunohost,dc=org`)

#### ldap_identifier

LDAP user identifier (**default**: `uid`)

#### ldap_attributes

User's attributes to fetch from LDAP (**default**: `["uid", "givenname", "sn", "cn", "homedirectory", "mail", "maildrop"]`)

#### allow_mail_authentication

Whether users can authenticate with their mail address (**default**: `true`)

#### login_arg

URI argument to use for cross-domain authentication (**default**: `sso_login`)

#### additional_headers

Array of additionnal HTTP headers to set once user is authenticated (**default**: `{ "Remote-User": "uid" }`)

#### session_timeout

The session expiracy time limit in seconds, since the last connection (**default**: `86400` / one day)

#### session_max_timeout

The session expiracy time limit in seconds (**default**: `604800` / one week)

#### protected_urls

List of priorily protected URLs and/or URIs (**by default, every URL is protected**)

#### protected_regex

List of regular expressions to be matched against URLs **and** URIs to protect them

#### skipped_urls

List of URLs and/or URIs that will not be affected by SSOwat

#### skipped_regex

List of regular expressions to be matched against URLs **and** URIs to ignore them

#### unprotected_urls

List of URLs and/or URIs that will not be affected by SSOwat **unless user is authenticated**

#### unprotected_regex

List of regular expressions to be matched against URLs **and** URIs to ignore them **unless user is authenticated**

#### redirected_urls

Array of URLs and/or URIs to redirect and their redirect URI/URL (**example**: `{ "/": "example.org/subpath" }`)

#### redirected_regex

Array of regular expressions to be matched against URLS **and** URIs and their redirect URI/URL (**example**: `{ "example.org/megusta$": "example.org/subpath" }`)

#### users

2-level array containing usernames and their allowed URLs along with an App name (**example**: `{ "kload": { "kload.fr/myapp/": "My App" } }`)

#### default_language

Language code used by default in views (**default**: `en`)
