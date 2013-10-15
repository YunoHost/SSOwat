SSOwat
======

A simple SSO for nginx, written in Lua

Requirements
------------

Nginx "Openresty" flavored : http://openresty.org/


Example Nginx conf
------------------

```nginx

lua_package_path "/usr/share/lua/5.1/nginx/?.lua;;"; # For Debian
init_by_lua_file path/to/init.lua;
access_by_lua_file path/to/access.lua;

# SSO domain
server {
    listen 80;
    server_name  mydomain.com;

    location = /ssowat/ {
       root /var/www/portal;
       index  login.html;
       add_header Content-Type text/html;
    }

    location = /whatever/ {

        ...

}

# Other domain
server {
    listen 80;
    server_name myotherdomain.com;

    ...

}

```
