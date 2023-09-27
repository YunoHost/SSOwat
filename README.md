SSOwat
======

A simple LDAP SSO for NGINX, written in Lua.

<a href="https://translate.yunohost.org/engage/yunohost/?utm_source=widget">
<img src="https://translate.yunohost.org/widgets/yunohost/-/287x66-white.png" alt="Translation status" />
</a>

- [Please report issues to the YunoHost bugtracker](https://github.com/YunoHost/issues).

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

- `cookie_secret_file`: Where the secret used for signing and encrypting cookie is stored. It should only be readable by root.
- `cookie_name`: The name of the cookie used for authentication. Its content is expected to be a JWT signed with the cookie secret and should contain a key `user` and `password` (which is needed for Basic HTTP Auth). Because JWT is only encoded and signed (not encrypted), the `password` is expected to be encrypted using the cookie secret.
- `portal_domain`: Domain of the authentication portal. It has to be a domain, IP addresses will not work with SSOwat (**Required**).
- `portal_path`: URI of the authentication portal (**default**: `/ssowat/`). This path **must** end with “`/`”.
- `domains`: List of handled domains (**default**: similar to `portal_domain`).
- `redirected_urls`: Array of URLs and/or URIs to redirect and their redirect URI/URL (**example**: `{ "/": "example.org/subpath" }`).
- `redirected_regex`: Array of regular expressions to be matched against URLs **and** URIs and their redirect URI/URL (**example**: `{ "example.org/megusta$": "example.org/subpath" }`).

### `permissions`

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
