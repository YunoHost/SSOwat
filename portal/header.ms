<html>
<meta http-equiv="Content-Type" content="text/html; charset=UTF-8" >
<head>
        <title>YunoHost</title>
        <link rel="stylesheet" href="assets/css/bootstrap.min.css" type="text/css"/>
</head>
<body>
<!-- Padding bootstrap style -->
<div class="row">
<div class="col-xs-1 visible-xs"></div>
<div class="col-sm-10 col-sm-offset-1 col-xs-10 col-xs-offest-1">
<div class="row">
<div class="col-sm-6 col-sm-offset-3 col-xs-12">

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

