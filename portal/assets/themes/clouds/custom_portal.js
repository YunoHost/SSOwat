/*
===============================================================================
 This JS file may be used to customize the YunoHost user portal *and* also
 will be loaded in all app pages if the app nginx's conf does include the
 appropriate snippet.

 You can monkeypatch init_portal (loading of the user portal) and
 init_portal_button_and_overlay (loading of the button and overlay...) to do
 custom stuff
===============================================================================
*/

/*
 * Monkeypatch init_portal to customize the app tile style
 *
init_portal_original = init_portal;
init_portal = function()
{
    init_portal_original();
    // Some stuff here
}
*/

/*
 * Monkey patching example to do custom stuff when loading inside an app
 *
init_portal_button_and_overlay_original = init_portal_button_and_overlay;
init_portal_button_and_overlay = function()
{
    init_portal_button_and_overlay_original();
    // Custom stuff to do when loading inside an app
}
*/
