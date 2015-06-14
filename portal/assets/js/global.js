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

});
