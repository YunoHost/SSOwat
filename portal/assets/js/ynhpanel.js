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
window.addEvent = function(el, eventName, callback, options) {
    if (el.addEventListener) {
        if (!options || typeof(options) !== "object") {
            options = {};
        }

        options.capture = false;
        el.addEventListener(eventName, callback, options);
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

  var _initDrag = function(e){
    if (e.type === "touchstart"){
      x_pos = e.touches[0].clientX;
      y_pos = e.touches[0].clientY;
    }

    selected = elem;
    x_elem = x_pos - selected.offsetLeft;
    y_elem = y_pos - selected.offsetTop;
  };

  var _shutDrag = function(e){
      selected = null;
  };

  var _onMove = function(e){
    // Get position
    x_pos = document.all ? window.event: e.pageX;
    y_pos = document.all ? window.event : e.pageY;

    if (e.type === "touchmove") {
        x_pos = e.touches[0].clientX;
        y_pos = e.touches[0].clientY;
    }

    if (selected !== null) {
      if (e.type === "touchmove"){
        event.preventDefault();
      }
      dragged = true;
      selected.style.left = (x_pos - x_elem) + 'px';
      selected.style.top = (y_pos - y_elem) + 'px';
    }
  };

  // Prevent native D'n'D behavior
  window.addEvent(elem, 'dragstart', function(e){
    window.eventPreventDefault(e);
  });

  // Start dragging
  window.addEvent(elem, 'mousedown', _initDrag);
  window.addEvent(elem, 'touchstart', _initDrag);

  // Will be called when user dragging an element
  window.addEvent(window, 'mousemove', _onMove);
  window.addEvent(window, 'touchmove', _onMove, {passive: false});

  // Destroy the object when we are done
  window.addEvent(window, 'mouseup', _shutDrag);
  window.addEvent(window, 'touchend', _shutDrag);
  window.addEvent(window, 'touchcancel', _shutDrag);

  // Handle click event
  window.addEvent(elem, 'click', function(e){
      // Prevent default event
      window.eventPreventDefault(e);

      // Do not propagate to other click event if dragged out
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


  // Create portal link
  var portal = document.createElement('a');
  portal.setAttribute('id', 'ynh-overlay-switch');
  portal.setAttribute('href', '/yunohost/sso/');
  portal.setAttribute('class', 'disableAjax');
  document.body.insertBefore(portal, null);

  // Portal link is draggable, for user convenience
  dragg('ynh-overlay-switch');

  // Create overlay element
  var overlay = document.createElement('iframe');
  overlay.src = "/yunohost/sso/info.html";
  overlay.setAttribute("id","ynh-overlay");
  overlay.setAttribute("style","opacity:0"); // make sure the overlay is invisible already when loading it

  document.body.insertBefore(overlay, null);

  // Get user's app
  var r = new XMLHttpRequest();
  r.open("GET", "/ynhpanel.json", true);
  r.onreadystatechange = function () {
    // Die if error
    if (r.readyState != 4 || r.status != 200) return;

    // Response is JSON
    response = JSON.parse(r.responseText);


    // Add portal stylesheet
    var portalStyle = document.createElement("link");
    portalStyle.setAttribute("rel", "stylesheet");
    portalStyle.setAttribute("type", "text/css");
    portalStyle.setAttribute("href", '/ynhpanel.css');
    document.getElementsByTagName("head")[0].insertBefore(portalStyle, null);

    // Bind YNH Button
    window.addEvent(portal, 'click', function(e){
      // Prevent default click
      window.eventPreventDefault(e);
      // Toggle overlay on YNHPortal button click
      Element.toggleClass(overlay, 'visible');
      Element.toggleClass(portal, 'visible');
      Element.toggleClass(document.querySelector('html'), 'ynh-panel-active');
      Element.toggleClass(overlay, 'ynh-active');

      if(overlay.classList.contains('ynh-active')) {
          meta_viewport.setAttribute('content', meta_viewport_content);
          Element.addClass(overlay, 'ynh-fadeIn');
          Element.removeClass(overlay, 'ynh-fadeOut');
        }else {
          meta_viewport.setAttribute('content', "width=device-width");
          Element.removeClass(overlay, 'ynh-fadeIn');
          Element.addClass(overlay, 'ynh-fadeOut');
        }
    });

  };
  r.send();


});
