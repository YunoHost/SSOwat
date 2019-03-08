var app_tile_colors = ['redbg','purpledarkbg','darkbluebg','orangebg','greenbg','darkbluebg','purpledarkbg','yellowbg','lightpinkbg','pinkbg','turquoisebg','yellowbg','lightbluebg','purpledarkbg', 'bluebg'];

function set_app_tile_style(el)
{
    // Select a color value from the App label
    randomColorNumber = parseInt(el.textContent, 36) % app_tile_colors.length;
    // Add color class.
    el.classList.add(app_tile_colors[randomColorNumber]);
}

Array.each(document.getElementsByClassName("app-tile"), set_app_tile_style);
