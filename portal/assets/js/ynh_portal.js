/*
===============================================================================
 This JS file is loaded :
 - in the YunoHost user portal
 - on every app page if the app nginx's conf does include the ynh snippet
===============================================================================
*/

/*
=====================
  Utilities
=====================
*/

/* Console log fix */
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
    if (el == null) { return; }
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

function make_element_draggable(id) {

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

    // We add listening event for the iframe itself ...
    // otherwise dragging the tile on the iframe doesn't
    // work properly.
    // We do this at click time to have a better chance
    // that the iframe's body is indeed loaded ...
    // (a bit hackish but meh)
    portalOverlay = document.getElementById("ynh-overlay").contentDocument.body;
    window.addEvent(portalOverlay, 'mousemove', _onMove);
    window.addEvent(portalOverlay, 'touchmove', _onMove, {passive: false});
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
};

/* ----------------------------------------------------------
  Main
---------------------------------------------------------- */
window.addEvent(document, 'DOMContentLoaded', function() {

    // 3 different cases :
    // - this script is loaded from inside an app
    // - this script is loaded inside the portal, inside an iframe/overlay activated by clicking the portal button inside an app
    // - this script is loaded inside the "regular" portal when going to /yunohost/sso.

    var in_app = ! document.body.classList.contains('ynh-user-portal');
    var in_overlay_iframe = (window.location != window.parent.location);

    if (in_app)
    {
        init_portal_button_and_overlay();
    }
    else
    {
        init_portal();
        if (in_overlay_iframe) { tweak_portal_when_in_iframe(); }
    }
});

//
// This function is called when ynh_portal.js is included in an app
//
// It will create the small yunohost "portal button" usually in the bottom
// right corner and initialize the portal overlay, shown when clicking the
// portal button meant to make it easier to switch between apps.
//
function init_portal_button_and_overlay()
{
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

  // Prepare and inject the portal overlay (what is activated when clicking on the portal button)
  var portalOverlay = document.createElement('iframe');
  portalOverlay.src = "/yunohost/sso/portal.html";
  portalOverlay.setAttribute("id","ynh-overlay");
  portalOverlay.setAttribute("style","visibility: hidden;"); // make sure the overlay is invisible already when loading it
  document.body.insertBefore(portalOverlay, null);

  // Inject portal button
  var portalButton = document.createElement('a');
  portalButton.setAttribute('id', 'ynh-overlay-switch');
  portalButton.setAttribute('href', '/yunohost/sso/');
  portalButton.setAttribute('class', 'disableAjax');
  document.body.insertBefore(portalButton, null);
  // Make portal button draggable, for user convenience
  make_element_draggable('ynh-overlay-switch');

  // Bind portal button
  window.addEvent(portalButton, 'click', function(e){
      // Prevent default click
      window.eventPreventDefault(e);
      // Toggle overlay on YNHPortal button click
      Element.toggleClass(document.querySelector('html'), 'ynh-panel-active');
      Element.toggleClass(portalOverlay, 'ynh-active');

      if (Element.hasClass(portalOverlay, 'ynh-active')) {
          meta_viewport.setAttribute('content', meta_viewport_content);
          Element.addClass(portalOverlay, 'ynh-fadeIn');
          Element.removeClass(portalOverlay, 'ynh-fadeOut');
      } else {
          meta_viewport.setAttribute('content', "width=device-width");
          Element.removeClass(portalOverlay, 'ynh-fadeIn');
          Element.addClass(portalOverlay, 'ynh-fadeOut');
      }
  });
}

//
// This function is called to initialize elements like the app tile colors and other things ...
//
function init_portal()
{

  window.addEvent(document.getElementById('add-mailalias'), "click", function() {
    // Clone last input.
    var inputAliasClone = document.querySelector('.mailalias-input').cloneNode(true);
    // Empty value.
    inputAliasClone.value = '';
    // Append to form-group.
    this.parentNode.insertBefore(inputAliasClone, this);
  });

  window.addEvent(document.getElementById('add-maildrop'), "click", function() {
    // Clone last input.
    var inputDropClone = document.querySelector('.maildrop-input').cloneNode(true);
    // Empty value.
    inputDropClone.value = '';
    // Append to form-group.
    this.parentNode.insertBefore(inputDropClone, this);
  });

  Array.each(document.getElementsByClassName("app-tile"), function(el) {
        // Set first-letter data attribute.
        el.querySelector('.first-letter').innerHTML = el.getAttribute("data-appname").substring(0, 2);
        // handle app links so they work both in plain info page and in the info iframe called from ynh_portal.js
        window.addEvent(el, 'click', function(event) {
            // if asked to open in new tab
            if (event.ctrlKey || event.shiftKey || event.metaKey
                || (event.button && event.button == 1)) {
                return
            }
            // if asked in current tab
            else {
                event.preventDefault();
                parent.location.href=this.href;
                return false;
            };
        });
  });
}

function tweak_portal_when_in_iframe()
{
    // Set class to body to show we're in overlay
    document.body.classList.add('in_app_overlay');
    let userContainer = document.querySelector('a.user-container');
    if (userContainer) {
        userContainer.classList.replace('user-container-info', 'user-container-edit');
        userContainer.setAttribute('href', userContainer
            .getAttribute('href')
            .replace('edit.html', ''));
        window.addEvent(userContainer, 'click', function(e) {
            e.preventDefault();
            e.stopPropagation();
            window.parent.location.href = userContainer.getAttribute('href');
        });
    }
    let logoutButton = document.getElementById('ynh-logout');
    if (logoutButton)
    {
        // We force to do the logout "globally", not just in the
        // iframe, otherwise after login out the url might still be
        // domain.tld/app which is weird ...
        window.addEvent(logoutButton, 'click', function(e) {
            e.preventDefault();
            e.stopPropagation();
            window.parent.location.href = logoutButton.getAttribute("href");
        });
    }
}
