<html>
<meta http-equiv="Content-Type" content="text/html; charset=UTF-8" >
<head>
        <title>{{title}}</title>
        <link rel="stylesheet" href="assets/css/bootstrap.min.css" type="text/css"/>
</head>
<body>
<div class="row">
<div class="col-sm-4 col-sm-offset-4">
<h1>{{title}}</h1>
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

