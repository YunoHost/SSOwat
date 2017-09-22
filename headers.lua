-- Redirect to the SSO if logout is in progress
if ngx.ctx.SSOwFullLogout then
    local next_cookie, back_url = ngx.ctx.SSOwFullLogout:match('^(.-)|(http.+)$')
    ngx.log(ngx.DEBUG, "LOGOUT STEP DONE; next: "..next_cookie..", back to: "..back_url)
    ngx.status = ngx.HTTP_TEMPORARY_REDIRECT
    ngx.header['Set-Cookie'] = {next_cookie}
    ngx.header.Location = back_url
end
