SSOwat
======

A simple SSO for nginx, written in Lua

Requirements
------------

Nginx "Openresty" flavored : http://openresty.org/
or nginx-extras in Debian wheezy-backports


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
    root /var/www/mydomain.com;

    location /ssowat {
       alias /var/www/ssowat;
       default_type text/html;
    }

    location /whatever {

        ...

    }
}

# Other domain
server {
    listen 80;
    server_name myotherdomain.com;
    root /var/www/myotherdomain.com;

    ...

}

```
