/* ----------------------------------------------------------
  Utilities
---------------------------------------------------------- */

/* Console log fix
-------------------------- */
if (typeof(console) === 'undefined') {
    var console = {};
    console.log = console.error = console.info = console.debug = console.warn = console.trace = console.dir = console.dirxml = console.group = console.groupEnd = console.time = console.timeEnd = console.assert = console.profile = function() {};
}


/* Array utilities
  https://github.com/Darklg/JavaScriptUtilities/blob/master/assets/js/vanilla-js/libs/vanilla-arrays.js
-------------------------- */
Array.contains = function(needle, haystack) {
    var i = 0,
        length = haystack.length;

    for (; i < length; i++) {
        if (haystack[i] === needle) return true;
    }
    return false;
};
Array.each = function(arrayToParse, callback) {
    var i = 0,
        length = arrayToParse.length;
    for (; i < length; i++) {
        callback(arrayToParse[i]);
    }
};



/* CSS classes utilities
  https://github.com/Darklg/JavaScriptUtilities/blob/master/assets/js/vanilla-js/libs/vanilla-classes.js
-------------------------- */
Element.getClassNames = function(element) {
    var classNames = [],
        elementClassName = element.className;
    if (elementClassName !== '') {
        elementClassName = elementClassName.replace(/\s+/g, ' ');
        classNames = elementClassName.split(' ');
    }
    return classNames;
};
Element.hasClass = function(element, className) {
    if (element.classList) {
        return element.classList.contains(className);
    }
    return Array.contains(className, Element.getClassNames(element));
};
Element.addClass = function(element, className) {
    if (element.classList) {
        element.classList.add(className);
        return;
    }
    if (!Element.hasClass(element, className)) {
        var elementClasses = Element.getClassNames(element);
        elementClasses.push(className);
        element.className = elementClasses.join(' ');
    }
};
Element.removeClass = function(element, className) {
    if (element.classList) {
        element.classList.remove(className);
        return;
    }
    var elementClasses = Element.getClassNames(element);
    var newElementClasses = [];
    var i = 0,
        arLength = elementClasses.length;
    for (; i < arLength; i++) {
        if (elementClasses[i] !== className) {
            newElementClasses.push(elementClasses[i]);
        }
    }
    element.className = newElementClasses.join(' ');
};
Element.toggleClass = function(element, className) {
    if (!Element.hasClass(element, className)) {
        Element.addClass(element, className);
    }
    else {
        Element.removeClass(element, className);
    }
};


/* Add Event
  https://github.com/Darklg/JavaScriptUtilities/blob/master/assets/js/vanilla-js/libs/vanilla-events.js
-------------------------- */
window.addEvent = function(el, eventName, callback) {
    if (el.addEventListener) {
        el.addEventListener(eventName, callback, false);
    }
    else if (el.attachEvent) {
        el.attachEvent("on" + eventName, function(e) {
            return callback.call(el, e);
        });
    }
};
window.eventPreventDefault = function(event) {
    return (event.preventDefault) ? event.preventDefault() : event.returnValue = false;
};


/* Draggable

  Sources :
  http://jsfiddle.net/5t3Ju/
  http://stackoverflow.com/questions/9334084/moveable-draggable-div
  http://jsfiddle.net/tovic/Xcb8d/light/
-------------------------- */

var dragg = function(id) {

  // Variables
  this.elem = document.getElementById(id),
  this.selected = null,  // Selected element
  this.dragged = false,  // Dragging status
  this.x_pos = 0, this.y_pos = 0, // Stores x & y coordinates of the mouse pointer
  this.x_elem = 0, this.y_elem = 0; // Stores top, left values (edge) of the element

  // Start dragging
  window.addEvent(elem, 'mousedown', function(e){
    // Prevent firefox native D'n'D behavior
    window.eventPreventDefault(e);

    selected = elem;
    x_elem = x_pos - selected.offsetLeft;
    y_elem = y_pos - selected.offsetTop;
  });

  // Will be called when user dragging an element
  window.addEvent(window, 'mousemove', function(e){
    // Get position
    x_pos = document.all ? window.event.clientX : e.pageX;
    y_pos = document.all ? window.event.clientY : e.pageY;

    if (selected !== null) {
      dragged = true;
      selected.style.left = (x_pos - x_elem) + 'px';
      selected.style.top = (y_pos - y_elem) + 'px';
    }
  });

  // Destroy the object when we are done
  window.addEvent(window, 'mouseup', function(e){
      selected = null;
  });

  // Handle click event
  window.addEvent(elem, 'click', function(e){
      // Prevent default event
      window.eventPreventDefault(e);

      // Do not prapagate to other click event if dragged out
      if (dragged) {
        e.stopImmediatePropagation();
      }
      // Reset dragging status
      dragged = false;
  });
}


/* Smallest DOMReady
  http://dustindiaz.com/smallest-domready-ever
-------------------------- */
function domReady(cb) {
   /in/.test(document.readyState) // in = loadINg
      ? setTimeout('domReady('+cb+')', 9)
      : cb();
}


/* ----------------------------------------------------------
  Main
---------------------------------------------------------- */
domReady(function(){
  // Don't do this in iframe
  if (window.self !== window.top) {return false;}

  // Set and store meta viewport
  var meta_viewport = document.querySelector('meta[name="viewport"]');
  if (meta_viewport === null) {
    meta_viewport = document.createElement('meta');
    meta_viewport.setAttribute('name', "viewport");
    meta_viewport.setAttribute('content', "");
    document.getElementsByTagName('head')[0].insertBefore(meta_viewport, null);
  }
  meta_viewport = document.querySelector('meta[name="viewport"]');
  meta_viewport_content = meta_viewport.getAttribute('content');

  // Add portal stylesheet
  var portalStyle = document.createElement("link");
  portalStyle.setAttribute("rel", "stylesheet");
  portalStyle.setAttribute("type", "text/css");
  portalStyle.setAttribute("href", '/ynhpanel.css');
  document.getElementsByTagName("head")[0].insertBefore(portalStyle, null);

  // Create portal link
  var portal = document.createElement('a');
  portal.setAttribute('id', 'ynh-overlay-switch');
  portal.setAttribute('href', '/yunohost/sso/');
  portal.setAttribute('class', 'disableAjax');
  document.body.insertBefore(portal, null);

  // Portal link is draggable, for user convenience
  dragg('ynh-overlay-switch');


  // Create overlay element
  var overlay = document.createElement("div");
  overlay.setAttribute("id","ynh-overlay");
  overlay.setAttribute("style","display:none");

  document.body.insertBefore(overlay, null);

  //Color Application
  var colors = ['redbg','purpledarkbg','darkbluebg','orangebg','greenbg','darkbluebg','purpledarkbg','yellowbg','lightpinkbg','pinkbg','turquoisebg','yellowbg','lightbluebg','purpledarkbg', 'bluebg'];

  // Get user's app
  var r = new XMLHttpRequest();
  r.open("GET", "/ynhpanel.json", true);
  r.onreadystatechange = function () {
    // Die if error
    if (r.readyState != 4 || r.status != 200) return;

    // Response is JSON
    response = JSON.parse(r.responseText);

    // Add overlay header
    overlay.innerHTML += '<div id="ynh-user" class="ynh-wrapper info">' +
                          '<ul class="ul-reset user-menu"><li><a class="icon icon-connexion disableAjax" href="'+ response.portal_url +'?action=logout">'+response.t_logout+'</a></li></ul>'+
                          '<a class="user-container user-container-info disableAjax" href="'+ response.portal_url +'edit.html">' +
                            '<h2 class="user-username">'+ response.uid +'</h2>' +
                            '<small class="user-fullname">'+ response.givenName + ' ' + response.sn +'</small>' +
                            '<span class="user-mail">'+ response.mail +'</span>' +
                          '</a>' +
                        '</div>';


    // Add application links
    var links = [];
    Array.prototype.forEach.call(response.app, function(app, n){
      randomColorNumber = parseInt(app.name, 36) % colors.length;
      links.push('<li><a class="'+colors[randomColorNumber]+' disableAjax" href="//'+app.url+'"><span class="first-letter" data-first-letter="'+ app.name.substr(0,2) +'"></span><span class="name">'+app.name+'</span></a></li>');
    });
    overlay.innerHTML += '<div id="ynh-apps" class="ynh-wrapper apps"><ul class="listing-apps">'+ links.join("\n") +'</ul></div>';

    // Add footer links
    overlay.innerHTML += '<div id="ynh-footer" class="ynh-wrapper footer"><nav>' + "\n" +
                          '<a class="link-profile-edit" href="/yunohost/sso/edit.html">'+ response.t_footerlink_edit +'</a>' + "\n" +
                          '<a class="link-documentation" href="//yunohost.org/docs" target="_blank">'+ response.t_footerlink_documentation +'</a>' + "\n" +
                          '<a class="link-documentation" href="//yunohost.org/support" target="_blank">'+ response.t_footerlink_support +'</a>' + "\n" +
                          '<a class="link-admin" href="/yunohost/admin/" target="_blank">'+ response.t_footerlink_administration +'</a>' + "\n" +
                        '</nav></div>';

    // Add overlay to DOM
    var btn = document.getElementById('logo'),
        yunoverlay = document.getElementById('ynh-overlay'),
        user = document.getElementById('ynh-user'),
        apps = document.getElementById('ynh-apps');

    var pfx = ["webkit", "moz", "MS", "o", ""];
    function PrefixedEvent(element, type, callback) {
      for (var p = 0; p < pfx.length; p++) {
        if (!pfx[p]) type = type.toLowerCase();
        element.addEventListener(pfx[p]+type, callback, false);
      }
    }

    // Bind YNH Button
    window.addEvent(portal, 'click', function(e){
      // Prevent default click
      window.eventPreventDefault(e);
      // Toggle overlay on YNHPortal button
      //Element.toggleClass(overlay, 'visible');
      Element.toggleClass(portal, 'visible');
      Element.toggleClass(document.querySelector('html'), 'ynh-panel-active');


      if(yunoverlay.classList.contains('ynh-active')) {
          meta_viewport.setAttribute('content', meta_viewport_content);
          yunoverlay.classList.add('ynh-fadeOut');
          PrefixedEvent(yunoverlay, "AnimationEnd", function(){
            if(yunoverlay.classList.contains('ynh-fadeOut')) {
              yunoverlay.classList.remove('ynh-active');
            }
          });
        }else {
          meta_viewport.setAttribute('content', "width=device-width");
          yunoverlay.classList.remove('ynh-fadeOut');
          yunoverlay.classList.add('ynh-active');
        }
    });

  };
  r.send();

});
