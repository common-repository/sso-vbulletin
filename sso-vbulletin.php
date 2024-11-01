<?php

/**
 * Plugin Name:       SSO vBulletin
 * Plugin URI:        https://www.extreme-idea.com/
 * Description:       The SSO vBulletin allows you to synchronize the WordPress authentication with the vBulletin.
 * Version:           1.2.0
 * Author:            EXTREME IDEA LLC
 * Author URI:        http://www.extreme-idea.com
 */

if (!defined('ABSPATH')) {
    exit; // Exit if accessed directly  
}

/* Definition of necessary constants and Load necessary files */
define('WVSSO_PRODUCT_NAME', 'SSO vBulletin');
define('WVSSO_REDIRECT_URL_PARAM', 'ssoredirect');
define('WVSSO_REDIRECT_LINK_TEXT', 'You can also <a href="%s">return to the page you were on</a>.');
define('WVSSO_ERROR_25_CHARS_TEXT', '<strong>ERROR</strong>: Username cannot be longer than 25 characters.');
define('WVSSO_ERROR_ILLEGAL_CHARS_TEXT', '<strong>ERROR</strong>: This username is invalid because it uses illegal characters. Please enter a valid username. Forbidden chars: %s');
define('WVSSO_ERROR_PASS_EQ_USERNAME_TEXT', 'Password should not be equal to username.');
define('WVSSO_USERNAME_VALID_MESSAGE', 'Username is valid and not in use.');
define('WVSSO_USER_REGISTERED_MESSAGE', 'To create your account, we must confirm your email address. '
    . 'Please click the Activation link that we just sent you. '
    . 'It should arrive within a few minutes. '
    . 'If you don\'t see it, please check your Spam or Junk folder to ensure the message was not filtered. '
    . 'If you have any issues, please email.');

/* If found profile builder plugin */

$profileBuilder = 'profile-builder/index.php';
$profileBuilderPro = 'profile-builder-pro/index.php';
$activePlugins = get_option('active_plugins');
define('WVSSO_PROFILE_BUILDER_ACTIVE', (in_array($profileBuilder, $activePlugins) or in_array($profileBuilderPro, $activePlugins)));
require_once(dirname(__FILE__) . '/config.php');
require_once(dirname(__FILE__) . '/includes/functions_ajax.php');
require_once(dirname(__FILE__) . '/includes/functions_logging_monolog.php');

new \com\extremeidea\wordpress\wordpress\vbulletin\sso\AdminSettingsPage();

//Disable plugin for /wp-admin/network. vBulletin files broke network settings on WP.
if (is_network_admin() && (FALSE !== strpos($_SERVER['REQUEST_URI'], 'network/setup.php') OR FALSE !== strpos($_SERVER['REQUEST_URI'], 'network/settings.php'))) {
    return TRUE;
}

/* Add actions to extend Wordpress and Profile Builder logic */

register_activation_hook(__FILE__, 'wvsso_register_activation_hook');
register_uninstall_hook(__FILE__, 'wvsso_register_uninstall_hook');

if (!wvsso_valid_bulletin_path()) {
    return;
}

define('WVSSO_FORUM_PATH', get_option(WVSSO_FORUM_PATH_NAME));
require_once(dirname(__FILE__) . '/vbulletin_handler.php');

global $vbulletin;
define('WVSSO_LOGIN_PAGE', $vbulletin->options['wvsso_login_url']);
define('WVSSO_REGISTER_PAGE', $vbulletin->options['wvsso_register_url']);
define('WVSSO_LOST_PASSWORD_PAGE', $vbulletin->options['wvsso_forgot_password_url']);
define('WVSSO_USERNAME_IN_USE_MESSAGE', 'That username is already in use or does not meet the administrator\'s standards. '
    . 'If you are %s and you have forgotten your password, '
    . '<a href="' . home_url() . WVSSO_LOST_PASSWORD_PAGE . '">click here</a>.');
define('WVSSO_RESET_PASSWORD_REQUIRED_MESSAGE', 'Your account has been upgraded to our new system. Please '
    . '<a style="color: #02b;" href="' . home_url() . WVSSO_LOST_PASSWORD_PAGE
    . '">click here</a> to reset your password.');

add_action('wp_authenticate', 'wvsso_authentication');
add_action('password_reset', 'wvsso_password_reset', 10, 2);
add_action('wppb_password_reset', 'wvsso_password_reset', 10, 2);
add_action('wp_logout', 'wvsso_vb_logout');
add_action('wp_login', 'wvsso_login', 10, 2);

add_action('wpmu_new_user', 'wvsso_user_register', 10, 1);
add_action('user_register', 'wvsso_user_register', 10, 1);
//add_filter('wppb_register_success_message', 'wvsso_wppb_register_success_message', 10, 1);

add_action('wppb_signup_user', 'wvsso_wppb_signup_user', 10, 4);

//we refused to use internal ProfileBuilder hook. see issue #3649
//add_action('wppb_activate_user', 'wvsso_wppb_activate_user', 10, 3);
add_action('profile_update', 'wvsso_profile_update', 10, 2);

add_action('wpmu_delete_user', 'wvsso_delete_user');
add_action('delete_user', 'wvsso_delete_user');

/* Add redirect link to registration process */
add_filter('wppb_output_fields_filter', 'wvsso_add_redirect_link_to_register_form', 10, 1);
add_filter('wppb_signup_user_notification_email_content', 'wvsso_wppb_signup_user_notification_email_content', 10, 4);
add_filter('wppb_success_email_confirmation', 'wvsso_wppb_success_email_confirmation', 10, 1);
add_filter('mustache_variable_ec_activation_link', 'wvsso_ec_replace_activation_link', 13, 4);

/* Custom validatation of Registration and Edit-Profile forms */
//Add restriction for username length: 25 chars
add_filter('wppb_check_form_field_default-username', 'wvsso_wppb_check_form_field_default_username', 10, 3);
add_filter('registration_errors', 'wvsso_wp_check_form_field_default_username', 10, 3);
add_action('admin_footer', 'wvsso_show_username_25_chars_warning');
//Add restriction for username and password: these fields shouldn't be equal
add_filter('wppb_check_form_field_default-password', 'wvsso_validate_default_password_field', 10, 3);
//Add custom script to Registration and Edit-Profile pages
add_action('wppb_before_register_fields', 'wvsso_before_register_and_profile_form');
add_action('wppb_before_edit_profile_fields', 'wvsso_before_register_and_profile_form');
//Reset `reset_passwd_required` flag if admin updates user's password through wp-admin
add_action('edit_user_profile_update', 'wvsso_update_extra_profile_fields', 10, 1);
//Log events
add_action('wppb_after_sending_email', 'wvsso_log_send_activation_email_to_user', 10, 6);
add_action( 'wppb_register_success', 'wvsso_log_user_success_registered');
//add_filter('wppb_register_success_message', 'wvsso_log_that_user_');
$profileBuilderIntegrate = get_option(WVSSO_PROFILE_BUILDER_INTEGRATE);

if (WVSSO_PROFILE_BUILDER_ACTIVE && $profileBuilderIntegrate) {
    //Redirect /wp-login.php?action=register to our custom registration page
    add_action('login_form_register', 'wvsso_default_register_page');

    // Redirect to login
    add_action('login_form_login', 'wvsso_default_login_page');

    //Redirect to custom Lost Password page
    add_action('lost_password', 'wvsso_lost_password_page_redirect');

}

//Make "Remember Me" checked by default
add_filter('wppb_login_form_args', 'wvsso_remember_me_make_checked', 10, 1);

/* AJAX for Registration form: We have to check is login available for registration */
add_action('wp_ajax_wvsso_check_login', 'wvsso_check_login_ajax');
add_action('wp_ajax_nopriv_wvsso_check_login', 'wvsso_check_login_ajax');
//Forbid some pages for redirect: login, registration and lost password pages.
add_filter('wppb_after_login_redirect_url', 'wvsso_filter_redirect_to', 10, 1);

//It is necessary for custom redirect mechanism (Profile Builder redirection is broken after failed login attempt).
//See issue #3529
add_action('login_init', function () {
    if (isset($_POST['wppb_referer_url']) && !wvsso_is_redirect_forbidden($_POST['wppb_referer_url'])) {
    }
    $_POST['wppb_request_url'] = esc_url_raw($_POST['wppb_request_url']) . '?' . WVSSO_REDIRECT_URL_PARAM . '=' . urlencode(esc_url_raw($_POST['wppb_referer_url']));
});

add_action('wp_print_styles', function () {
    wp_enqueue_style('wvsso_style', plugins_url('/includes/assets/css/style.css', __FILE__));
});

//Add custom redirect. See issue #3529
add_filter('login_form_bottom', function ($html) {
    $redirect_to = isset($_GET[WVSSO_REDIRECT_URL_PARAM]) ? esc_url_raw($_GET[WVSSO_REDIRECT_URL_PARAM]) : false;

    //YO! Here we can set correct redirection URL after failed login.
    //Profile Builder will get HTTP_REFERER and set into wppb_referer_url input field of login form.
    if ($redirect_to) {
        $_SERVER['HTTP_REFERER'] = $redirect_to;
    }
    return $html;
}, 2, 1);

//Filters to log all possible activation errors:
add_filter('wppb_register_activate_user_error_message1', 'wvsso_log_activation_error', 10, 1);
add_filter('wppb_register_activate_user_error_message2', 'wvsso_log_activation_error', 10, 1);
add_filter('wppb_register_activate_user_error_message4', 'wvsso_log_activation_error', 10, 1);
add_filter('wppb_register_activate_user_error_message5', 'wvsso_log_activation_error', 10, 1);
add_filter('wppb_register_failed_user_activation', 'wvsso_log_activation_error', 10, 1);

//Validate username if registration launched from WP-ADMIN. Check illegal chars and length
add_filter('user_profile_update_errors', 'wvsso_user_profile_update_errors', 10, 3);

function wvsso_user_profile_update_errors($errors, $update, $user) {
    if ($user && isset($user->user_login)) {
        $error_text = wvsso_wppb_check_form_field_default_username('', '', array('username' => $user->user_login));

        if ($error_text) {
            $errors->add('username_invalid', $error_text);
        }
    }
}

function wvsso_log_activation_error($message) {
    if (isset($_REQUEST['activation_key'])) {
        $message = strip_tags($message);
        $message .= ' Activation key: ' . sanitize_text_field($_REQUEST['activation_key']) . '. See `wp_signups` table for details.';
    }
    wvsso_log_error("Profile Builder activation error: " . $message);
}

function wvsso_filter_redirect_to($redirect_to = '') {
    return wvsso_is_redirect_forbidden($redirect_to) ? home_url() : $redirect_to;
}

function wvsso_is_redirect_forbidden($current_page) {
    $forbidden_pages = explode(' ', get_option(WVSSO_OPTION_NAME_FORBIDDEN_PAGES));
    foreach ($forbidden_pages as $page) {
        if (false !== strpos($current_page, $page)) {
            wvsso_log_info("WP: Forbidden page detected: current page: '$current_page', forbidden page: '$page'");
            return true;
        }
    }
    return false;
}


function wvsso_lost_password_page_redirect() {
    wp_redirect(WVSSO_LOST_PASSWORD_PAGE);
}

function wvsso_remember_me_make_checked($form_args) {
    $form_args['value_remember'] = TRUE;
    return $form_args;
}

function wvsso_default_register_page() {
    wp_redirect(WVSSO_REGISTER_PAGE);
}

function wvsso_default_login_page() {
    wp_redirect(WVSSO_LOGIN_PAGE);
}

/** Reset `reset_passwd_required` flag if admin updates user's password through wp-admin
 *
 * @param type $user_id
 */
function wvsso_update_extra_profile_fields($user_id) {
    $user = get_userdata($user_id);
    if (current_user_can('edit_user', $user_id) && $user && wvsso_is_pswd_reset_required($user->user_login) && '' != wvsso_get_password()) {
        wvsso_log_info("WP: Update extra profile fields for user: id: '$user_id', field: reset_passwd_required, value: 0");
        update_user_meta($user_id, 'reset_passwd_required', 0);
    }
}

/** Provide the same restirction as on vBulletin side: 'Password should not be equal to username.'
 *
 * @param type $a unknown variable from filter
 *     'wppb_check_form_field_default-password'
 * @param type $field
 * @param type $global_request
 * @param type $form_type
 * @return type
 */
function wvsso_validate_default_password_field($a, $field, $global_request) {
    $username = $global_request['username'] ? $global_request['username'] : (is_user_logged_in() ? wp_get_current_user()->user_login : '');

    if ($username === $global_request['passw1'] && $username) {
        return WVSSO_ERROR_PASS_EQ_USERNAME_TEXT;
    }
}

/** Show custom message after successful registration
 *
 * @param type $standart_text
 * @return type string
 */
function wvsso_wppb_register_success_message($standart_text) {
    return WVSSO_USER_REGISTERED_MESSAGE;
}

function wvsso_before_register_and_profile_form() {
    wp_enqueue_script('wvsso-custom-script', plugins_url('/includes/assets/js/script.js', __FILE__), array('jquery'));
    wp_localize_script('wvsso-custom-script', 'wvsso_ajax', array(
            'url' => admin_url('admin-ajax.php')
        )
    );
}

function wvsso_show_username_25_chars_warning() {
    if ($GLOBALS['pagenow'] == 'user-new.php') {
        ?>
        <script type="text/javascript">
            jQuery(document).ready(function () {
                jQuery('#user_login').attr('maxlength', 25);
                jQuery('#user_login').after('<label for="user_login">Max length: 25 characters.</label>');
            });
        </script>
        <?php

    }
}

/** Username custom validation func. Checks whether username is less than 25 chars or contains invalid chars.
 *
 * @param type $param
 * @param type $field
 * @param type $global_request
 * @return type Error if username is invalid
 */
function wvsso_wppb_check_form_field_default_username($param, $field, $global_request) {
    $userName = $global_request['username'];
    check_form_fields($userName);
}


function wvsso_wp_check_form_field_default_username($errors, $sanitized_user_login, $user_email) {
    $error = check_form_fields(sanitize_text_field($_POST['user_login']));

    if ($error) {
        $errors->add('wvsso_error', $error);
    }

    return $errors;
}

function check_form_fields($userName) {
    if (strlen($userName) > 25) {
        return WVSSO_ERROR_25_CHARS_TEXT;
    }
    if (!wvsso_check_illegal_chars($userName)) {
        return sprintf(WVSSO_ERROR_ILLEGAL_CHARS_TEXT, get_option(WVSSO_OPTION_NAME_ILLEGAL_CHARS));
    }
    return null;
}

/** Adds redirection link to page with successful activation message
 *
 * @param type $message
 * @return string Message with additional link
 */
function wvsso_wppb_success_email_confirmation($message) {

    if (isset($_GET[WVSSO_REDIRECT_URL_PARAM]) && (strpos($_GET[WVSSO_REDIRECT_URL_PARAM], get_site_url()) !== FALSE)) {
        return $message . wvsso_get_redirection_link_html(esc_url(urldecode($_GET[WVSSO_REDIRECT_URL_PARAM])));
    }
}

function wvsso_ec_replace_activation_link($value, $merge_tag_name, $merge_tag, $extra_data) {
    $activation_key = $extra_data['email_confirmation_key'];

    return wvsso_add_redirect_link_to_confirmation_email($value, $activation_key);
}

function wvsso_wppb_signup_user_notification_email_content($message, $user_email, $user, $activation_key) {
    return wvsso_add_redirect_link_to_confirmation_email($message, $activation_key);
}

/** Adds redirection link to activation link in order to send it by email and show it later (in `wppb_success_email_confirmation` filter)
 *
 * @param type $message
 * @param type $user_email
 * @param type $user
 * @param type $activation_key
 * @return string
 */
function wvsso_add_redirect_link_to_confirmation_email($message, $activation_key) {
    $referer_url = '';
    $post_referer_url = isset($_POST[WVSSO_REDIRECT_URL_PARAM]) ? esc_url_raw($_POST[WVSSO_REDIRECT_URL_PARAM])
        : (isset($_POST['wppb_referer_url']) ? esc_url_raw($_POST['wppb_referer_url']) : '');

    if ((strpos($post_referer_url, get_site_url()) !== FALSE)) {
        $referer_url = '&' . WVSSO_REDIRECT_URL_PARAM . '=' . urlencode($post_referer_url);
    }
    wvsso_log_info("WP: Add redirect link to confirmation email: activation key '$activation_key', referrer: '$referer_url'");
    return str_replace($activation_key, $activation_key . $referer_url, $message);
}

/** Adds input field to register form in order to show correct redirection link later
 *
 * @param string $output_fields
 * @return string
 */
function wvsso_add_redirect_link_to_register_form($output_fields) {
    $referer_url = '';
    if (!empty($_POST) && isset($_POST['wppb_referer_url']) && 'register' == $_POST['action'] && !wvsso_is_redirect_forbidden($_POST['wppb_referer_url'])) {
        $referer_url = isset($_POST[WVSSO_REDIRECT_URL_PARAM]) ? $_POST[WVSSO_REDIRECT_URL_PARAM] : $_POST['wppb_referer_url'];
        $referer_url = esc_url_raw($referer_url);
        $output_fields .= '<input type="hidden" name="' . WVSSO_REDIRECT_URL_PARAM . '" value="' . $referer_url . '">';
    }
    wvsso_log_info("WP: Add redirect link to register form: referrer: '$referer_url'");
    return $output_fields;
}

function wvsso_delete_user($user_id) {
    wvsso_log_info("WP: Delete user started, user id: $user_id");
    $user = get_userdata($user_id);

    wvsso_vb_delete($user->user_email, $user->user_login);
}

function wvsso_profile_update($user_id, $old_user_data) {
    wvsso_log_info("WP: Update user profile started, user id: $user_id");
    $new_user_data = get_userdata($user_id);
    if (!$new_user_data) {
        wvsso_log_error(
                "WP: Something goes wrong. User {$user_id} has updated profile. But we can not fetch his info from DB"
        );
        return false;
    }

    $new_user_email = '';
    $new_user_password = '';
    $oldEmail = $old_user_data->get('user_email');
    $newEmail = $new_user_data->get('user_email');
    if ($newEmail !== $oldEmail) {
        $new_user_email = $newEmail;
    }

    if ('' !== wvsso_get_password()) {
        $new_user_password = wvsso_get_password();
    }

    wvsso_vb_update_user($oldEmail, $new_user_email, $new_user_password, $old_user_data->get('user_login'));
}

/** Called if registration is from Profile Builder Registration Form and "Email Confirmation" Activated: Yes
 *
 * @param type $user_id
 * @return void
 */
function wvsso_wppb_signup_user($username, $user_email, $activation_key, $meta) {
    wvsso_log_info("Profile builder hook: sign up user started: name: $username, email: $user_email, key: $activation_key");
    wvsso_vb_user_register($username, $user_email, wvsso_get_password(), FALSE);

    add_action('wppb_after_sending_email', function () { ?>
        <script type="text/javascript">
            jQuery('body').addClass('wvsso-hide-header');
        </script>
    <?php });
}

/** Called during user activation process - when user is being copyed from wp_signups table to wp_users
 *
 * @param type $user_id
 * @return boolean
 */
function wvsso_user_register($user_id) {
    wvsso_log_info("WP: Register user: user id: $user_id");
    $user = get_userdata($user_id);
    if (!$user || !isset($user->data->user_login) || !isset($user->data->user_email)) {
        wvsso_log_error('WP: Something goes wrong. Wordpress could not receive userdata with userid='
            . intval($user_id) . '. Or user does not containg login or email.');
        return false;
    }

    $isProfileBuilderAdminConfirm = isset($_POST['action']) && isset($_POST['todo'])
        && $_POST['action'] == 'wppb_handle_email_confirmation_cases' && $_POST['todo'] == 'confirm';

    if ('' !== wvsso_get_password() && !isset($_REQUEST['activation_key']) && !$isProfileBuilderAdminConfirm) {
        wvsso_vb_user_register($user->data->user_login, $user->data->user_email, wvsso_get_password(), TRUE);
    }

    wvsso_vb_activate_user($user->data->user_email);
    return TRUE;
}

function wvsso_login($user_login, $user) {
    wvsso_log_info("WP: Login action: user: $user_login, email: {$user->user_email}");
    //"REMEMBER ME" Checkbox:
    $rememberme = (isset($_POST['rememberme']) && !empty($_POST['rememberme'])) ? true : false;

    wvsso_vb_login($user->user_email, $rememberme, $user_login);
}

/** Function shows reset-password page
 *
 * @param type $login username or email
 */
function wvsso_authentication($login) {
    if ((username_exists($login) || email_exists($login)) && wvsso_is_pswd_reset_required($login)) {
        wvsso_log_info("WP: Authentication reset password action for user: $login");
        $dir = plugin_dir_path(__FILE__);
        include($dir . "reset-password-page.php");
        die();
    }
}

function wvsso_password_reset($user, $new_pass) {
    wvsso_log_info("WP: Reset password action: user: '$user'");
    //'wppb_reset_password' action sends USERID in 1st param instead of $USER object (as core action does)
    $user = (is_string($user) or is_int($user)) ? get_userdata($user) : $user;

    if ('1' === get_user_meta($user->ID, 'reset_passwd_required', true)) {
        wvsso_log_info("WP: Update user meta field: 'reset_passwd_required' to 0");
        update_user_meta($user->ID, 'reset_passwd_required', 0);
    }

    wvsso_vb_update_user($user->user_email, '', $new_pass, $user->get('user_login'));
}

function wvsso_is_pswd_reset_required($login) {
    $user = username_exists($login) ? get_user_by('login', $login) : get_user_by('email', $login);
    if ('WP_User' != get_class($user)) {
        return FALSE;
    }

    if ('1' === get_user_meta($user->ID, 'reset_passwd_required', true)) {
        return TRUE;
    }

    return FALSE;
}

/** Returns password from registration form (including admin registration form and Profile Builder Reg Form)
 *
 * @return string password
 */
function wvsso_get_password() {
    //passw1 - name of the input of ProfileBuilder Registration form
    //pass1 -  name of the input of wp-admin Registration form
    $password = isset($_POST['passw1']) ? $_POST['passw1'] : '';
    if ('' === $password && isset($_POST['pass1'])) {
        $password = $_POST['pass1'];
    }

    return $password ? $password : md5(time());
}

function wvsso_register_activation_hook() {

}

function wvsso_register_uninstall_hook() {

}

function wvsso_get_redirection_link_html($url) {
    $html = '<p class="wvsso-redirect-link">';
    $html .= sprintf(WVSSO_REDIRECT_LINK_TEXT, $url);
    $html .= '</p>';

    return $html;
}

function wvsso_valid_bulletin_path() {
    if (!is_file(get_option(WVSSO_FORUM_PATH_NAME) . '/includes/config.php')) {
        return false;
    }
    return true;
}

function wvsso_log_send_activation_email_to_user($sent, $to, $subject, $message, $send_email, $context) {
    if ($context == 'email_user_activate') {
        $result = $sent ? 'success' : 'fail';
        wvsso_log_info("WP: Sent confirmation email to '$to', result: $result");
    }
}

function wvsso_log_user_success_registered($request) {
    wvsso_log_info("WP: User {$request['username']} success registered!, email: {$request['email']}");
}

add_action('init', 'wvsso_register_shutdown_log_function');
function wvsso_register_shutdown_log_function() {
    if (get_option(WVSSO_OPTION_NAME_LOG_PHP_ERRORS)) {
        register_shutdown_function('wvsso_shutdown_log');
    }
}
