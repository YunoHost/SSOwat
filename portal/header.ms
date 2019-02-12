<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <title>{{t_portal}}</title>

  <!-- Responsive -->
  <meta name="format-detection" content="telephone=no" />
  <meta name="viewport" content="width=device-width, height=device-height, initial-scale=1" />

  <!-- Do not index SSOWat pages -->
  <meta name="robots" content="noindex, nofollow">

  <!-- Stylesheets -->
  <link rel="stylesheet" href="assets/css/ynh-style.css">
  <link rel="stylesheet" href="assets/themes/{{theme_name}}.css">

  <!-- Icons -->
  <link rel="shortcut icon" href="assets/icons/favicon.ico">
  <link rel="apple-touch-icon" sizes="57x57" href="assets/icons/apple-touch-icon-57x57.png">
  <link rel="apple-touch-icon" sizes="114x114" href="assets/icons/apple-touch-icon-114x114.png">
  <link rel="apple-touch-icon" sizes="72x72" href="assets/icons/apple-touch-icon-72x72.png">
  <link rel="apple-touch-icon" sizes="144x144" href="assets/icons/apple-touch-icon-144x144.png">
  <link rel="apple-touch-icon" sizes="60x60" href="assets/icons/apple-touch-icon-60x60.png">
  <link rel="apple-touch-icon" sizes="120x120" href="assets/icons/apple-touch-icon-120x120.png">
  <link rel="apple-touch-icon" sizes="76x76" href="assets/icons/apple-touch-icon-76x76.png">
  <link rel="apple-touch-icon" sizes="152x152" href="assets/icons/apple-touch-icon-152x152.png">
  <link rel="icon" type="image/png" href="assets/icons/favicon-196x196.png" sizes="196x196">
  <link rel="icon" type="image/png" href="assets/icons/favicon-160x160.png" sizes="160x160">
  <link rel="icon" type="image/png" href="assets/icons/favicon-96x96.png" sizes="96x96">
  <link rel="icon" type="image/png" href="assets/icons/favicon-16x16.png" sizes="16x16">
  <link rel="icon" type="image/png" href="assets/icons/favicon-32x32.png" sizes="32x32">
  <meta name="msapplication-TileColor" content="#41444f">
  <meta name="msapplication-TileImage" content="/mstile-144x144.png">
</head>
<body class="{{#connected}}logged{{/connected}}">

  <h1 id="logo" class="logo">
      <img src="assets/img/logo-ynh-white.svg"/><span class="element-invisible">Yunohost</span>
  </h1>

  <div class="overlay">
    {{#flash_win}}
    <div class="wrapper messages success">{{.}}</div>
    {{/flash_win}}

    {{#flash_fail}}
    <div class="wrapper messages danger">{{.}}</div>
    {{/flash_fail}}

    {{#flash_info}}
    <div class="wrapper messages info">{{.}}</div>
    {{/flash_info}}
