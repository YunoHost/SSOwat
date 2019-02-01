
// function dynamicallyLoadScript(url) {
//     var script = document.createElement("script");  // create a script DOM node
//     script.src = "/assets/themes/clouds/js/ynhpanel.js";  // set its src to the provided URL
//
//     document.head.appendChild(script);  // add it to the end of the head section of the page (could change 'head' to 'body' to add it to the end of the body section instead)
// }
//
// function loadScript(url, callback)
// {
//     // Adding the script tag to the head as suggested before
//     var head = document.head;
//     var script = document.createElement('script');
//     script.type = 'text/javascript';
//     script.src = url;
//
//     // Then bind the event to the callback function.
//     // There are several events for cross browser compatibility.
//     script.onreadystatechange = callback;
//     script.onload = callback;
//
//     // Fire the loading
//     document.body.appendChild(script);
// }
//
// // RANDOMIZATION UTILITIES
// var random = {
//   integer: function(min, max){
//     if (_.isArray(min)) return random.integer(min[0], min[1]);
//     return Math.floor(Math.random() * (max - min + 1)) + min;
//   },
//   rgbInteger: function () { return random.integer(0,255); },
//   // generate random rgba color
//   color: function (transparency) {
//     // transparency
//     var transparency;
//     if (transparency === null || transparency === false) transparency = 1
//     else if (typeof transparency == "number") transparency = transparency
//     else transparency = $$.random.number (0,1);
//     // random color
//     return [ random.rgbInteger(), random.rgbInteger(), random.rgbInteger(), transparency ];
//   },
// };

// COLOR HANDLING UTILITIES
var colorify = {

  // rgbColor <[number, number, number(, number)]>
  toCSS: function (rgbColor) {
    // rgba color
    if (rgbColor.length == 4) return "rgba("+ rgbColor[0] +","+ rgbColor[1] +","+ rgbColor[2] +","+ rgbColor[3] +")"
    // rgb color
    else return "rgb("+ rgbColor[0] +","+ rgbColor[1] +","+ rgbColor[2] +")";
  },

  // Luminosity function adpated from color library: https://github.com/Qix-/color
  // rgbColor <[number, number, number]>
  luminosity: function (rgbColor) {
    // http://www.w3.org/TR/WCAG20/#relativeluminancedef

    var lum = [];
    for (var i = 0; i < rgbColor.length; i++) {
      var chan = rgbColor[i] / 255;
      lum[i] = (chan <= 0.03928) ? chan / 12.92 : Math.pow(((chan + 0.055) / 1.055), 2.4);
    }

    return 0.2126 * lum[0] + 0.7152 * lum[1] + 0.0722 * lum[2];
  },

  // color <[number, number, number]>
  getContrastColor: function (color) {
    var light = "white", dark = "black";
    return colorify.luminosity(color) > 0.5 ? dark : light;
  },

  // convert a string into an array of four strings
  splitAppNameForRgba: function (appName) {
    var portions = [ "", "", "", "" ];
    for (i=0; i < appName.length; i++) { portions[i%4] += appName[i]; }
    return portions;
  },

  // convert a string into an rgba color array
  randomColorFromAppName: function (appName) {
    var appNamePortions = colorify.splitAppNameForRgba(appName);
    return [
      parseInt(appNamePortions[0], 36) % 255,
      parseInt(appNamePortions[1], 36) % 255,
      parseInt(appNamePortions[2], 36) % 255,
      (parseInt(appNamePortions[3], 36) % 100) / 100,
    ];
  },

};


var liMenu = document.querySelectorAll('#apps a')
liMenu && [].forEach.call(liMenu, function(el, i) {
  var appColor = colorify.randomColorFromAppName(el.textContent);
  var appContrastColor = colorify.getContrastColor(appColor);
  el.setAttribute("style", 'background-color:'+ colorify.toCSS(appColor) +' !important; color:'+ appContrastColor +' !important;')
});
