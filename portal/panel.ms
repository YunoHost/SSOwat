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
<!--<body class="gradient" style="">-->
<iframe name="glu" id="glu" width="100%" src="/" style=""></iframe>
<script>
var ynh = {};
ynh.jquery = jQuery.noConflict();
(function( $ ) {

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
            }, 300);
        });
    }

    preventRefire = false;
    function checkScroll (direction) {
        if(preventRefire) return;

        if((direction == "top") && ($("body").scrollTop() == 107 || $("html").scrollTop() == 107) && $("#ynhtoggle.ynhopen").length == 0) {
            datScroll(0);
        } else if((direction == "bottom") && $("#ynhtoggle.ynhopen").length > 0) {
            datScroll(h);
        }
    }

    $( document ).ready(function($) {
        scroll = $("body").scrollTop();
        h = 107;
        $('body').children().filter(function() {
            return $(this).css("position") === 'absolute' ||  $(this).css("position") === 'fixed';
        }).css({top: function(index, value) {
                return parseFloat(value) + h + 3;
        }});
        if ($(window).height() > $("html").height()) {
            alert('moualé');
            $("html").css('min-height', $(window).height() + h );
        }
        $("body").append('<div id="ynhtopbar"><div id="ynhtoggle" class="ynhopen">YunoHost</div></div>');
        $("body").css({marginTop: function(index, value) {
            return parseFloat(value) + h + 3;
        }});
        if (scroll == 0) {
            $("body,html").animate({scrollTop:h}, '100', 'swing', function() {
                setTimeout(function() { 
                    $("#ynhtoggle").removeClass("ynhopen");
                }, 300);
                //window.scrollTo(0, h);
            });
        }
        $("#ynhtoggle").on("click", function() {
            if ($("body").scrollTop() == 0 && $("html").scrollTop() == 0) {
                datScroll(h);
            } else {
                datScroll(0);
            }                                                                                                                                                                                    
        });

        $("#glu").load(function() {
            $( $(this)[0].contentWindow ).bind("DOMMouseScroll mousewheel scroll", function(event) {
                if (event.currentTarget.scrollY > 0) {
                    checkScroll("bottom");
                } else {
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
