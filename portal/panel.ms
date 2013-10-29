<!doctype html>
<!--[if lt IE 7]> <html class="no-js lt-ie9 lt-ie8 lt-ie7" lang="en"> <![endif]-->
<!--[if IE 7]> <html class="no-js lt-ie9 lt-ie8" lang="en"> <![endif]-->
<!--[if IE 8]> <html class="no-js lt-ie9" lang="en"> <![endif]-->
<!--[if gt IE 8]><!--> <html class="no-js" lang="en"> <!--<![endif]-->
<head>
<meta charset="utf-8">
<meta http-equiv="X-UA-Compatible" content="IE=edge,chrome=1">
<meta name="format-detection" content="telephone=no" />
<meta name="viewport" content="user-scalable=no, width=device-width, height=device-height" />
<title>Yunohost Apps</title>
<link media="all" type="text/css" href="assets/css/panel.css" rel="stylesheet">
<script src="assets/js/jquery-1.10.2.min.js"></script>
</head>
<body class="gradient" style="overflow: hidden">
<iframe name="glu" id="glu" width="100%" src="/" style=""></iframe>
<script>
var ynh = {};
ynh.jquery = jQuery.noConflict();
(function( $ ) {

    preventFire = false;
    preventRefire = false;
    function datScroll(to) {
        preventRefire = true;
        $("body,html").animate({scrollTop:to}, '100', 'swing', function() {
            setTimeout(function() {
                if (to == 0) {
                    $("#ynhtoggle").addClass("ynhopen");
                } else {
                    $("#ynhtoggle").removeClass("ynhopen");
                }
                preventRefire = false;
            }, 200);
        });
    }

    function checkScroll (direction) {
        if(preventRefire) return;

        if((direction == "top") && ($("body").scrollTop() == 107 || $("html").scrollTop() == 107) && $("#ynhtoggle.ynhopen").length == 0) {
            if(preventFire) return;
            datScroll(0);
        } else if((direction == "bottom") && $("#ynhtoggle.ynhopen").length > 0 ) {
            datScroll(h);
        }
    }

    function changeTitle() {
        if (top.glu.document.title)
            top.document.title = top.glu.document.title;
        else
            top.document.title = 'Yunohost Apps';
    }
    var tid = setInterval(changeTitle, 10000);

    $( document ).ready(function($) {
        h = 107;

        $("#glu").load(function() {

            setTimeout(function() {
                changeTitle();
                if ($("#ynhtopbar").length == 0) {
                    $('body').children().filter(function() {
                        return $(this).css("position") === 'absolute' ||  $(this).css("position") === 'fixed';
                    }).css({top: function(index, value) {
                        return parseFloat(value) + h + 3;
                    }});
                    $("body").append('<div id="ynhtopbar"><div id="ynhtoggle" class="ynhopen">YunoHost</div></div>');
                    {{#app}}
                    $("#ynhtopbar").append('<div class="ynhapp" data-href="https://{{url}}"><div class="ynhappsquare">R</div><div class="ynhappcaption">{{name}}</div></div>');
                    {{/app}}
                }
                $("body").css({marginTop: function(index, value) {
                    return parseFloat(value) + h + 3;
                }});
                if ($("body").scrollTop() == 0) {
                        $("body,html").scrollTop(h);
                        $("#ynhtoggle").removeClass("ynhopen");
                }
                $("#ynhtoggle").on("click", function() {
                        preventFire = false;
                        checkScroll("bottom");
                        checkScroll("top");
                });
  
                $(".ynhapp").on("click", function(event) {
                    event.preventDefault();
                    parent.glu.location.href = $(this).attr('data-href');
                    $('.ynhapp.active').removeClass('active');
                    $(this).addClass('active');
                });
            }, 10);

            $(window).resize(function() {
                if ($("#ynhtoggle.ynhopen").length == 0) {
                    $("body,html").scrollTop(h);
                }
            });

            $( $(this)[0].contentWindow ).bind("DOMMouseScroll mousewheel scroll", function(event) {
                if ((event.type == "DOMMouseScroll" && event.originalEvent.detail > 0)
                ||  (event.type == "mousewheel" && event.originalEvent.wheelDeltaY < 0)
                ||   event.currentTarget.scrollY > 0 ) {
                    checkScroll("bottom");
                    preventFire = true;
                } else {
                    setTimeout(function() { preventFire = false; }, 500);
                    checkScroll("top");
                }
            });
            $(document).bind("keyup keydown",function(event){
                if($('input:focus,textarea:focus').length > 0) return; //If an input field is focused
                if(event.which == 38 || event.which == 33) {
                    checkScroll("top");
                } else if(event.which == 40 || event.which == 34) {
                    checkScroll("bottom");
                }

            });
        });
    });
})(ynh.jquery);
</script>
</body>
</html>
