<?php

if (!defined('ABSPATH')) {
    exit; // Exit if accessed directly  
}

function wvsso_check_login_ajax() {
    if (isset($_REQUEST['action']) && 'wvsso_check_login' === $_REQUEST['action'] && '' !== $_REQUEST['username']) {

        $error_status = 'error';
        $ok_status = 'ok';

        $status = '';
        $message = '';

        $username = $_REQUEST['username'];

        if (!wvsso_check_illegal_chars($username)) {
            $status = $error_status;
            $message = sprintf(WVSSO_ERROR_ILLEGAL_CHARS_TEXT, get_option(WVSSO_OPTION_NAME_ILLEGAL_CHARS));
        } elseif (strlen($username) > 25) {
            $status = $error_status;
            $message = WVSSO_ERROR_25_CHARS_TEXT;
        } elseif (FALSE === username_exists($username) && !wvsso_signup_get_user_by_username($username)) {
            $status = $ok_status;
            $message = WVSSO_USERNAME_VALID_MESSAGE;

        } else {
            $status = $error_status;
            $message = sprintf(WVSSO_USERNAME_IN_USE_MESSAGE, $username);

        }

        echo(json_encode(array('status' => $status, 'msg' => $message)));
    }
    exit();
}

//Extra functions for SignUp process
function wvsso_signup_get_user_by_username($username) {
    global $wpdb;

    $username = sanitize_user($username);
    $sql_result = $wpdb->get_row($wpdb->prepare("SELECT * FROM " . $wpdb->base_prefix . "signups WHERE user_login = %s", $username), ARRAY_A);

    return $sql_result ? $sql_result : false;
}

function wvsso_check_illegal_chars($username) {
    $illegal_chars = preg_split('/[ \r\n\t]+/', get_option(WVSSO_OPTION_NAME_ILLEGAL_CHARS), -1, PREG_SPLIT_NO_EMPTY);

    foreach ($illegal_chars as $char) {
        if (strpos(strtolower($username), strtolower($char)) !== false) {
            return false;
        }
    }

    return true;
}
