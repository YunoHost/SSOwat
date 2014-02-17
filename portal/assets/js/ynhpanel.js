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

  // Add portal stylesheet
  var portalStyle = document.createElement("link");
  portalStyle.setAttribute("rel", "stylesheet");
  portalStyle.setAttribute("type", "text/css");
  portalStyle.setAttribute("href", '/ynhpanel.css');
  document.getElementsByTagName("head")[0].insertBefore(portalStyle, null);

  // Create portal link
  var portal = document.createElement('a');
  portal.setAttribute('id', 'ynhportal');
  portal.setAttribute('href', '/ynhsso/');
  document.body.insertBefore(portal, null);

  // Get user's app
  var r = new XMLHttpRequest();
  r.open("GET", "/ynhpanel.json", true);
  r.onreadystatechange = function () {
    // Die if error
    if (r.readyState != 4 || r.status != 200) return;

    // Response is JSON
    response = JSON.parse(r.responseText);

    // Create overlay element
    var overlay = document.createElement("div");
    overlay.setAttribute("id","ynhoverlay");

    // Append close button
    var closeBtn = document.createElement("div");
    closeBtn.setAttribute("id","ynhclose");
    closeBtn.innerHTML = "X";
    overlay.insertBefore(closeBtn, null);

    // Add overlay header
    overlay.innerHTML += '<div class="header">' +
                        '<h1>'+ response.user +'</h1>' +
                        '<a class="account-link" href="'+ response.portal_url +'">View my account</a>' +
                        '</div>';

    // Add application links
    var links = [];
    Array.each(response.app, function(app){
      links.push('<li><a href="//'+app.url+'" data-first-letter="'+ app.name.substr(0,1) +'">'+app.name+'</a></li>');
    });
    overlay.innerHTML += '<ul>'+ links.join('') +'</ul>';

    // Add overlay to DOM
    document.body.insertBefore(overlay, null);          

    // Bind YNH Button
    window.addEvent(portal, 'click', function(e){
      // Prevent default click
      window.eventPreventDefault(e);
      // Toggle overlay on YNHPortal button
      Element.toggleClass(overlay, 'visible');
    });

    // Bind close button
    window.addEvent(document.getElementById('ynhclose'), 'click', function(e){
      // Prevent default click
      window.eventPreventDefault(e);
      // Hide overlay
      Element.removeClass(overlay, 'visible');
    });

  };
  r.send();

});
