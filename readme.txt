=== SSO vBulletin ===

Contributors: extremeidea
Tags: sso, single sign-on, login, registration, user management, authentication, vbulletin, bridge
Requires at least: 4.4
Tested up to: 5.6
Stable tag: trunk
License: GPLv2 or later
License URI: http://www.gnu.org/licenses/gpl-2.0.html
Donate link: https://www.paypal.com/cgi-bin/webscr?cmd=_s-xclick&hosted_button_id=LM25KRQVLRLDS 
Contact Us: https://www.extreme-idea.com/

== Description ==

<h1>Important!!!</h1>
<p style="background-color: red;">
This plugin is deprecated and was renamed as WP vBulletin SSO. All future changes will be released only in scope of WP vBulletin SSO plugin. </p> <a href="https://wordpress.org/plugins/wp-vbulletin-sso/">Go to WP vBulletin SSO plugin</a>

The plugin is developed and supported by <a href="https://www.extreme-idea.com/">Extreme Idea LLC</a>. Our entire team is ready to help you. Ask your questions in the support forum, or <a href="https://www.extreme-idea.com/contact-us/">contact us directly</a>.

== Installation == 

To Install the SSO plugin on WordPress: 
1. Log in as administrator to WordPress Admin Panel. 
2. Navigate to Plugins > press Add New button > press Upload Plugin button. 
3. Browse for sso vbulletin.zip file > press Install Now button. 
4. The plugin should be successfully installed (navigate to Plugins > press Installed Plugins button > navigate to the WordPress vBulletin SSO extension). 

To Install the SSO extension on vBulletin site: 
1. Log in to forum`s /admincp/ Control Panel as administrator: 
2. Navigate to Plugins & Products section. 
3. Expand section and click on the Manage Products link. 
4. Scroll down right frame until you find Add/Import Product link. 
5. Click on the link and choose for sso vbulletin.xml file (extract the file from the archive). 
6. Click on the Import button. 
7. Change vBulletin Login Link: Log in as vBulletin Administrator → Open Styles and Templates → Add next changes to the current theme:

Comment or remove next lines out in template `header`: <form id="navbar_loginform" ... till </form>. 
Paste the link right after the commented out form: <a rel="nofollow" class="guest-login" href="{vb:raw vboptions.sso_login_url}">Login</a> (or simply replace all code with the last link of this form).

== Uninstallation ==

To Uninstall the SSO extension: 
1. Log in as WordPress administrator to WordPress Admin Panel: 
2. Navigate to Plugins > press Installed Plugins button > navigate to the SSO vBulletin extension. 
3. Press Deactivate button. 
4. Press Delete button. The plugin should be successfully deleted. 

To Uninstall the extension via the vBulletin dashboard: 
1. Log in to your forum’s /admincp/ control panel as administrator. 
2. Navigate to the Plugins & Products section. 
3. Expand section and click on the Manage Products link. 
4. Find vBulletin SSO extension and select Uninstall it. 

== Upgrade Notice ==

To update the plugin:

1. Log in as administrator to Admin Panel.
2. Uninstall the plugin (see Uninstall chapter).
3. (Re)install the plugin (see Install chapter).
The plugin should be successfully re-installed.

== Configuration ==

To open the SSO vBulletin plugin settings page: Log in as WordPress administrator > Settings > SSO vBulletin
Here you can:
Enable / Disable Email Notification (by default this features is disabled).
Set Email Address(es) for Email Notifications.
Set Illegal User names and characters.

To open the SSO vBulletin plugin settings page navigate to : Settings > Options > SSO vBulletin

There are available next redirection fields:

“Login Url” field - enter the URL you would like to be redirected to (after Login button is pressed).
“Register Url” field - enter the URL you would like to be redirected to (after Register button is pressed).
“Lost Password Url ”field - enter the URL you would like to be redirected to (after Lost Password button is pressed).
“Change Password and Email Url” field - enter the URL you would like to be redirected to (after Change Password and Email button is pressed).

== Error Log ==

Errors are stored at WORDPRESS_ROOT/wp-content/uploads/sso-vbulletin-logs

== Screenshots ==

1. screenshot-1.png

2. screenshot-2.png

== Changelog ==

= 1.2.0 = 2018-10-25

* Added Secondary User Groups feature: Admin can specify category ID to synchronize newly registered users with this group(s).
* Fixed an issue during adding new user by Admin (via wp-admin).

= 1.1.2 = 2018-12-03

* Fixed plugin`s version.

= 1.1.1 = 2018-12-03

* Fixed an issue when user`s primary usergroup is "Users Awaiting Email Confirmation" after email confirmation via Admin Panel.

= 1.1.0 = 2018-19-02

* Changed logger instance, added log section to a settings page.

= 1.0.4 = 2017-12-01

* Fixed an error during profile update if user has an empty character in user name.

= 1.0.3 = 2017-12-01

* Fixed an error during reset password.

= 1.0.2 = 2017-06-07

* Added unique function names, defines, and classnames.
* Changed the place of saving its files (outside of the plugins folder).  
* Vanished the Hardcode.

= 1.0.1 =  2017-05-29

* Changed the plugin name.
* Renamed function names, defines, and classnames.
* Added sanitization, escape, and validation to plugin POST calls.

= 1.0.0 = 2017-05-18

* First release.

Important! This plugin is deprecated and was renamed as WP vBulletin SSO. All future changes will be released only in scope of WP vBulletin SSO plugin. <a href="https://wordpress.org/plugins/wp-vbulletin-sso/">More info about the WP vBulletin SSO plugin</a>

