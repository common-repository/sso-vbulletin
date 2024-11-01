<?php

if (!defined('ABSPATH')) {
    exit; // Exit if accessed directly  
}

if (defined('WVSSO_FORUM_PATH')) {

    chdir(WVSSO_FORUM_PATH);
    require_once('./includes/config.php');
    require_once('./global.php');
    require_once(DIR . '/includes/functions_login.php');
}

//Fix: some plugins (Disqus e.g.) doesn't work. see #3565
unset($_POST['ajax']);

//2 - id of "Registered users" group on Forum side by default
//3 - id of "Users Awaiting Email Confirmation" group by default
define('WVSSO_VBULLETIN_REGISTERED_USERS_GROUP_ID', 2);
define('WVSSO_VBULLETIN_USERS_AWAITING_CONFIRMATION_GROUP_ID', 3);

/**
 * Updates user data: email and password
 * 
 * @param string $old_email old email
 * @param string $new_email new email
 * @param string $new_password  new password
 *
 * @return mixed
 */
function wvsso_vb_update_user($old_email, $new_email, $new_password, $wp_username = '') {
    global $vbulletin;
    wvsso_log_info(
        "vBulletin update user stated: wp user name: '$wp_username', email: '$old_email', new email: '$new_email'"
    );
    $userdata = wvsso_vb_load_user($old_email);
    if (!$userdata) {
        wvsso_log_error(sprintf(WVSSO_UPDATE_USER_ERROR_TEXT, $old_email));
        return FALSE;
    }

    if (empty($new_email) && empty($new_password)) {
        wvsso_log_warning("vBulletin update user: user email '$old_email', Nothing to update, email and password is empty!");
        return FALSE;
    }

    if ('' !== $new_password) {
        wvsso_log_info("vBulletin update user: '$old_email', set new password.");
        $userdata->set('password', $new_password);
    }
    if ('' !== $new_email) {
        wvsso_log_info("vBulletin update user: '$old_email', set new email: '$new_email'.");
        $userdata->set('email', $new_email);
    }

    wvsso_check_username($wp_username, $userdata->existing['username'], 'Update');
    wvsso_vb_save_user($userdata);

    $userdata = datamanager_init('user', $vbulletin, ERRTYPE_STANDARD);
    $userdata->set_existing($vbulletin->userinfo);

    $vbulletin->GPC['newpassword'] = $new_password;
    $vbulletin->GPC['email'] = $new_email;
    
    ($hook = vBulletinHook::fetch_hook('profile_updatepassword_complete')) ? eval($hook) : false;
}

/** Logs user out from vBulletin
 * 
 */
function wvsso_vb_logout() {
    process_logout();
}

/** Delete user out from vBulletin DB
 * 
 */
function wvsso_vb_delete($email, $wp_username) {
    wvsso_log_info("vBulletin delete user: '$email'.");
    $userinfo = wvsso_vb_load_user($email);

    if (!$userinfo) {
        wvsso_log_error(sprintf(WVSSO_DELETE_USER_ERROR_TEXT, $email));
        return FALSE;
    }

    wvsso_check_username($wp_username, $userinfo->existing['username'], 'Delete');

    if (!$userinfo->delete()) {
        if (!empty($userinfo->errors)) {
            foreach ($userinfo->errors as $error) {
                wvsso_log_error($error);
            }
        } else {
            wvsso_log_error(sprintf(WVSSO_DELETE_USER_UNKNOWN_ERROR_TEXT, $email));
        }
    }
    unset($userinfo);
}

/** Logs user in to vBulletin
 * 
 */
function wvsso_vb_login($email, $rememberme = false, $username) {
    global $vbulletin;
    $user = $vbulletin->userinfo; // object exists for both guest and authenticated user always.

    if ($user['email'] != $email) {

        $userid = wvsso_get_userid_from_email($email);

        if ($userid === FALSE) {
            wvsso_log_error(sprintf(WVSSO_LOGIN_USER_ERROR_TEXT, $email));
            return FALSE;
        }

        $userinfo = wvsso_vb_load_user($email);

        if (!$userinfo) {
            return FALSE;
        }

        $vbulletin->userinfo = $userinfo->existing;
        wvsso_check_username($username, $userinfo->existing['username']);

        if (!wvsso_is_error_data_item($vbulletin->userinfo)) {
            if ($user['userid'] != $vbulletin->userinfo['userid']) {
                vbsetcookie('userid', $vbulletin->userinfo['userid'], true, true, true);
                vbsetcookie('password', md5($vbulletin->userinfo['password'] . COOKIE_SALT), true, true, true);
                exec_unstrike_user($vbulletin->userinfo['username']);

                $logintype = ($vbulletin->userinfo['usergroupid'] == '6') ? 'cplogin' : '';
                process_new_login($logintype, $rememberme, TRUE);
            }
        } else {
            return array('error' => $vbulletin->userinfo);
        }
    }
}

/** Adds user in to vBulletin
 * 
 * @global type $vbulletin
 * @param type $username
 * @param type $email
 * @param type $password
 * @param type $is_user_registered false - if activation on WP side needed, true - if registration process called from wp-admin or Email Confirmation option is disabled
 * @return type
 */
function wvsso_vb_user_register($username, $email, $password, $is_user_registered) {
    global $db, $vbulletin;
    wvsso_log_info("vBulletin register new user: '$username', email: '$email', registered: " . (int)$is_user_registered);
    $usergroup_id = $is_user_registered ? WVSSO_VBULLETIN_REGISTERED_USERS_GROUP_ID : WVSSO_VBULLETIN_USERS_AWAITING_CONFIRMATION_GROUP_ID;
    wvsso_log_info("vBulletin register new user: user group id: $usergroup_id");
    $userdata = datamanager_init('User', $vbulletin, ERRTYPE_ARRAY);
    $userdata->set('username', $username);
    $userdata->set('email', $email);
    $userdata->set('password', $password);
    $userdata->set('usergroupid', $usergroup_id);
    $memberGroups = wvsso_get_member_groups();
    if ($memberGroups) {
        $userdata->set('membergroupids', $memberGroups);
    }
    $userid = wvsso_vb_save_user($userdata);
    $userinfo =  fetch_userinfo($userid);
    $vbulletin->userinfo = $userinfo;

    ($hook = vBulletinHook::fetch_hook('register_addmember_complete')) ? eval($hook) : false;

    return $userdata;
}

function wvsso_get_member_groups()
{
    global $vbulletin;
    $secondaryGroupsIds = $vbulletin->options['wvsso_secondary_user_groups'];
    $secondaryGroupsIds = explode(',', $secondaryGroupsIds);
    $memberGroups = [];
    if ($secondaryGroupsIds) {
        $vbulletinGroupsIds = array_column($vbulletin->usergroupcache, 'title', 'usergroupid');
        foreach ($secondaryGroupsIds as $secondaryGroupId) {
            if (isset($vbulletinGroupsIds[$secondaryGroupId])) {
                $memberGroups[] = $secondaryGroupId;
                wvsso_log_info("Added secondary group '$vbulletinGroupsIds[$secondaryGroupId]' to user");
                continue;
            }
            // Error secondary group not found in vbulletin groups
            wvsso_log_error("Register user action: Secondary group id '$secondaryGroupId' not found in vbulletin groups");
        }
    }
    return $memberGroups;
}

/** Assign user to "Registered users" group after his activation on WP
 * 
 * @param type $email
 * @return boolean
 */
function wvsso_vb_activate_user($email) {
    $userdata = wvsso_vb_load_user($email);

    if (!$userdata) {
        wvsso_log_error(sprintf(WVSSO_ACTIVATE_USER_ERROR_TEXT, $email));
        return FALSE;
    }

    wvsso_log_info("Activation process started. Email: $email");

    $is_set = $userdata->set('usergroupid', strval(WVSSO_VBULLETIN_REGISTERED_USERS_GROUP_ID));
    if ($is_set && $userdata->setfields['usergroupid'] && empty($userdata->errors)) {
        wvsso_vb_save_user($userdata);
    } else {
        wvsso_log_error('Could not set `usergroupid` to activate. Email: ' . $email);
    }
}

function wvsso_vb_load_user($email) {
    global $vbulletin;

    $userid = wvsso_get_userid_from_email($email);
    $userdata = datamanager_init('User', $vbulletin, ERRTYPE_ARRAY);

    $userinfo = fetch_userinfo($userid);

    if (!is_array($userinfo)) {
        wvsso_log_error(sprintf(WVSSO_LOAD_USER_ERROR_TEXT, $email));
        return FALSE;
    }

    $userdata->set_existing($userinfo);
    return $userdata;
}

/** Returns user id from vBulletin by email
 * 
 * @global type $vbulletin
 * @global type $config
 * @param type $email
 * @return userid or false
 */
function wvsso_get_userid_from_email($email) {
    global $vbulletin, $config;

    $vbulletin->db->sql = "SELECT userid FROM " . $config['Database']['tableprefix'] . "user WHERE email = '" . $vbulletin->db->escape_string(trim($email)) . "'";
    $result = $vbulletin->db->execute_query(true, $vbulletin->db->connection_recent);

    if ($user = $vbulletin->db->fetch_array($result)) {
        return $user['userid'];
    } else {
        wvsso_log_error("vBulletin get user id: $email, user not found!");
        return false;
    }
}

function wvsso_vb_save_user($userdata) {
    global $vbulletin;

    $userdata->pre_save();
    if (!empty($userdata->errors)) {
        wvsso_log_error(WVSSO_SAVE_USER_ERROR_TEXT);
        foreach ($userdata->errors as $error) {
            wvsso_log_error($error);
        }
        return FALSE;
    }

    return $userdata->save();
}

function wvsso_is_error_data_item($data) {
    return is_array($data) && isset($data['message']);
}

/** Compares usernames from WordPress and from vBulletin and log error if they are not equal
 * 
 * @param type $wp_username
 * @param type $vb_username
 * @param type $action Name of the action where comparison executed. 'Login', 'Update', 'Delete' etc
 * @return boolean
 */
function wvsso_check_username($wp_username, $vb_username, $action = 'Login') {
    if (strcasecmp($wp_username, $vb_username) !== 0) {
        wvsso_log_error(sprintf(WVSSO_USERNAME_DISCREPANCY_ERROR_TEXT, $action, $wp_username, $vb_username));
        return FALSE;
    }
    return TRUE;
}
