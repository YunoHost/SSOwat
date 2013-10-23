<html>
<meta http-equiv="Content-Type" content="text/html; charset=UTF-8" >
<head>
    <meta name="format-detection" content="telephone=no" />
    <meta name="viewport" content="user-scalable=no, width=device-width, height=device-height" />
    <title>YunoHost Portal</title>
    <link rel="stylesheet" href="assets/css/bootstrap.min.css" type="text/css"/>
    <script src="assets/js/jquery-1.10.2.min.js"></script>
</head>
<body>
<!-- Padding bootstrap style -->
<div class="row">
<div class="col-xs-1 visible-xs"></div>
<div class="col-sm-10 col-sm-offset-1 col-xs-10 col-xs-offest-1">
<div class="row">
<div class="col-sm-8 col-sm-offset-2 col-xs-12" style="max-width: 750px;">

<h2>{{{title}}}</h2>
{{#connected}}
<div class="pull-right" style="margin-top: -31px">
    <a href="?action=logout">Logout</a>
</div>
{{/connected}}
<hr>

{{#flash_win}}
<div class="alert alert-success">{{.}}</div>
{{/flash_win}}

{{#flash_fail}}
<div class="alert alert-danger">{{.}}</div>
{{/flash_fail}}

{{#flash_info}}
<div class="alert alert-info">{{.}}</div>
{{/flash_info}}

