document.addEventListener('DOMContentLoaded', function() {

  // Variables
  var liMenu = document.querySelectorAll('#apps a')
    , colors = ['bluebg','purplebg','redbg','orangebg','greenbg','darkbluebg','lightbluebg','yellowbg','lightpinkbg']
    , addMailAlias = document.getElementById('add-mailalias')
    , addMaildrop = document.getElementById('add-maildrop')
  ;

  liMenu && [].forEach.call(liMenu, function(el, i) {
    // Add color class.
    el.classList.add(colors[i%colors.length]);
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