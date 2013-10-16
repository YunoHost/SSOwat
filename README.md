SSOwat
======

A simple LDAP SSO for nginx, written in Lua

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

```bash
git clone https://github.com/Kloadut/SSOwat /etc/ssowat
nano /etc/ssowat/conf.json
```

Nginx conf
----------

```bash
nano /etc/nginx/conf.d/ssowat.conf
```

```nginx

init_by_lua_file   /etc/ssowat/init.lua;
access_by_lua_file /etc/ssowat/access.lua;

server {
    listen 80; # Do not forget HTTPS for production

    location /sso {
       alias /etc/ssowat/portal;
       default_type text/html;
       index index.html;
    }
}

```

**That's it !**
