
var ynhLib = {

  //
  //                              RANDOMIZATION UTILITIES

  random: {
    integer: function(min, max){
      return Math.floor(Math.random() * (max - min + 1)) + min;
    },
    number: function (min, max) {
      return Math.random() * (max - min) + min;
    },
    entry: function (array) {
      return array[ynhLib.random.integer(0, array.length-1)];
    },
    rgbInteger: function () { return ynhLib.random.integer(0,255); },
    // generate random rgba color
    color: function (transparency) {
      // transparency
      var transparency;
      if (transparency === null || transparency === false) transparency = 1
      else if (typeof transparency == "number") transparency = transparency
      else transparency = ynhLib.random.number (0,1);
      // random color
      return [ ynhLib.random.rgbInteger(), ynhLib.random.rgbInteger(), ynhLib.random.rgbInteger(), transparency ];
    },
  },

  //
  //                              COLOR HANDLING UTILITIES

  color: {

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
      return ynhLib.color.luminosity(color) > 0.5 ? dark : light;
    },

  },

  //
  //                              UTILITIES

  queue: function (queueTo, queue) {
    if (typeof queueTo != 'function') var fullQueue = queue
    else if (typeof queue != 'function') var fullQueue = queueTo
    else var fullQueue = function () {
      queueTo.apply(this, arguments);
      queue.apply(this, arguments);
    };
    return fullQueue;
  },

  onWindowLoad: function(func){
    window.onload = ynhLib.queue(window.onload, func);
  },

  //
  //                              SET APP ICON STYLE

  set_app_tile_style: function (el) {
    var appColor = ynhLib.random.color();
    var appContrastColor = ynhLib.color.getContrastColor(appColor);
    var style = 'background-color:'+ ynhLib.color.toCSS(appColor) +' !important; color:'+ appContrastColor +' !important; --background-color:'+ ynhLib.color.toCSS(appColor);
    el.setAttribute("style", style);
  },

  //
  //                              LOGO CUSTOMIZATION

  logo: {

    availableColors: ["cyan", "fushia", "green", "orange", "pink", "purple", "red", "yellow"],
    makeLogoStyleString: function () {
      return 'background-image: url("/yunohost/sso/assets/themes/random/logo/'+ ynhLib.random.entry(ynhLib.logo.availableColors) +'.svg")';
    },

  },

};

// ######################################################################
// ######################################################################

ynhLib.onWindowLoad(function () {

  // set apps colors
  Array.each(document.getElementsByClassName("app-tile"), ynhLib.set_app_tile_style);

  // log color css string
  var chosenLogoStyleString = ynhLib.logo.makeLogoStyleString();

  // set logo color in portal
  var ynhLogo = document.getElementById("ynh-logo");
  if (ynhLogo) ynhLogo.setAttribute("style", chosenLogoStyleString);

  // set overlay switch color in apps (NOTE: this is not always working, there is probably a problem of loading order)
  var overlaySwitch = document.getElementById("ynh-overlay-switch");
  if (overlaySwitch) overlaySwitch.setAttribute("style", chosenLogoStyleString);

});
