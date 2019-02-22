// FIXME : this stuff is really weird given that global.js
// is ran on all pages, even if you are not logged in ...
// Maybe add a check. I noticed that if the user is logged in,
// there's a "logged" class added to the body.
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

  // handle app links so they work both in plain info page and in the info iframe called from ynhpanel.js
  var app_tiles = document.getElementsByClassName("app-tile");
  if (app_tiles) {
    for (var i = 0; i < app_tiles.length; i++) {
        app_tiles[i].addEventListener('click', function(event) {
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
        }, false);
     }
  }

  // FIXME - I don't understand what this do ...
  // This looks kinda hackish :|
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
