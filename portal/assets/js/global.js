
// scripts loader
function loadScript(url, callback) {
  var script = document.createElement('script');
  script.type = 'text/javascript';
  script.src = url;
  // There are several events for cross browser compatibility.
  script.onreadystatechange = callback;
  script.onload = callback;
  // Fire the loading
  document.head.appendChild(script);
}

// handle app links so they work both in plain info page and in the info iframe called from ynhpanel.js
function appClick (evnt, url) {

  // if asked to open in new tab
  if (
    evnt.ctrlKey ||
    evnt.shiftKey ||
    evnt.metaKey ||
    (evnt.button && evnt.button == 1)
  ) return

  // if asked in current tab
  else {
    evnt.preventDefault();
    parent.location.href= url;
    return false;
  };

}

document.addEventListener('DOMContentLoaded', function() {

  // Variables
  var liMenu = document.querySelectorAll('#apps a')
    , colors = ['redbg','purpledarkbg','darkbluebg','orangebg','greenbg','darkbluebg','purpledarkbg','yellowbg','lightpinkbg','pinkbg','turquoisebg','yellowbg','lightbluebg','purpledarkbg', 'bluebg']
    , addMailAlias = document.getElementById('add-mailalias')
    , addMaildrop = document.getElementById('add-maildrop')
  ;

  liMenu && [].forEach.call(liMenu, function(el, i) {
    // Select a color value from the App label
    randomColorNumber = parseInt(el.textContent, 36) % colors.length;
    //randomColorNumber = i%colors.length; // Old value
    // Add color class.
    el.classList.add(colors[randomColorNumber]);
    // Set first-letter data attribute.
    el.querySelector('.first-letter').setAttribute('data-first-letter',el.textContent.substring(0, 2));
  });

  addMailAlias && addMailAlias.addEventListener('click', function(){
    // Clone last input.
    var inputAliasClone = document.querySelector('.mailalias-input').cloneNode(true);
    // Empty value.
    inputAliasClone.value = '';
    // Append to form-group.
    addMailAlias.parentNode.insertBefore(inputAliasClone, addMailAlias);
  });

  addMaildrop && addMaildrop.addEventListener('click', function(){
    // Clone last input.
    var inputDropClone = document.querySelector('.maildrop-input').cloneNode(true);
    // Empty value.
    inputDropClone.value = '';
    // Append to form-group.
    addMaildrop.parentNode.insertBefore(inputDropClone, addMaildrop);
  });


  // Get user's infos
  var r = new XMLHttpRequest();
  r.open("GET", "/ynhpanel.json", true);
  r.onreadystatechange = function () {
    // Die if error
    if (r.readyState != 4 || r.status != 200) return;
    // Response is JSON
    response = JSON.parse(r.responseText);

  };
  r.send();

  if(window.location != window.parent.location) {
    // Set class to body to show we're in overlay
    document.body.classList.add('overlay');
      let userContainer = document.querySelector('a.user-container');
      userContainer.classList.replace('user-container-info', 'user-container-edit');
      userContainer.setAttribute('href', userContainer
          .getAttribute('href')
          .replace('edit.html', ''));
      userContainer.addEventListener('click', function(e) {
          e.preventDefault();
          e.stopPropagation();
          window.parent.location.href = userContainer.getAttribute('href');
      })
  }

});
