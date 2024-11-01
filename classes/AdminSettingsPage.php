<?php

namespace com\extremeidea\wordpress\wordpress\vbulletin\sso;

if (!defined('ABSPATH')) {
    exit; // Exit if accessed directly
}

define('WVSSO_FORUM_PATH_NAME', 'wvsso_forum_path_val');
define('WVSSO_OPTION_NAME_ILLEGAL_CHARS', 'wvsso_illegal_chars');
define('WVSSO_PROFILE_BUILDER_INTEGRATE', 'wvsso_profile_builder_integrate');
define('WVSSO_OPTION_NAME_FORBIDDEN_PAGES', 'wvsso_forbidden_pages');
define('WVSSO_OPTION_NAME_LOGGING_LEVEL', 'wvsso_logging_level');
define('WVSSO_OPTION_NAME_LOG_PHP_ERRORS', 'wvsso_log_php_errors');

class AdminSettingsPage
{
    protected $logManager;

    public function __construct()
    {
        $this->logManager = new ManageLogFiles();

        add_action('admin_menu', array($this, 'addAdminSettings'));
        add_action('init', array($this, 'manageLogFiles'));
    }

    public function addAdminSettings()
    {
        if (is_admin()) {
            add_options_page(
                WVSSO_PRODUCT_NAME . ' Options', WVSSO_PRODUCT_NAME,
                'manage_options',
                'wvsso_options',
                array($this, 'settings')
            );
        }
    }

    public function settings()
    {
        if (!current_user_can('manage_options')) {
            wp_die('You do not have sufficient permissions to access this page.');
        }

        if (isset($_POST['submit_options']) && $_POST['submit_options'] == 1
            && check_admin_referer('wvsso_save_settings')) {
            update_option(WVSSO_FORUM_PATH_NAME, sanitize_text_field(stripslashes($_POST[WVSSO_FORUM_PATH_NAME])));
            update_option(WVSSO_OPTION_NAME_ILLEGAL_CHARS,
                sanitize_text_field(stripslashes($_POST[WVSSO_OPTION_NAME_ILLEGAL_CHARS])));
            update_option(WVSSO_PROFILE_BUILDER_INTEGRATE,
                sanitize_text_field($_POST[WVSSO_PROFILE_BUILDER_INTEGRATE]));
            update_option(WVSSO_OPTION_NAME_FORBIDDEN_PAGES,
                sanitize_text_field(stripslashes($_POST[WVSSO_OPTION_NAME_FORBIDDEN_PAGES])));
            update_option(WVSSO_OPTION_NAME_LOGGING_LEVEL,
                sanitize_text_field(stripslashes($_POST[WVSSO_OPTION_NAME_LOGGING_LEVEL])));
            update_option(WVSSO_OPTION_NAME_LOG_PHP_ERRORS, $_POST[WVSSO_OPTION_NAME_LOG_PHP_ERRORS]);
            if (!wvsso_valid_bulletin_path()) {
                $this->showWpMessage('error', 'Wrong vBulletin forum path!', 'Please enter a valid forum path');
            }
        }
        include dirname(__FILE__) . '/../template/settings.php';
    }

    public function manageLogFiles() {
        if (isset($_POST['wvssoLoggingForm']) && $_POST['wvssoLoggingForm'] == 'post') {
            $file = WVSSO_LOGGING_PATH . '/' .  $_POST['wvssoLoggingFormFilename'];
            switch ($_POST['wvssoLoggingFormAction']) {
                case 'wvssoDownloadAll':
                    $this->logManager->downloadAllLogs();
                    break;
                case 'wvssoRemoveAll':
                    $this->logManager->removeAllLogs();
                    break;
                case 'wvssoDownload':
                    $this->logManager->downloadLog($file);
                    break;
                case 'wvssoRemove':
                    $this->logManager->removeLog($file);
                    break;
            }
        }
    }

    protected function showWpMessage($type, $message, $subMesssage = '')
    {
        echo "
            <div class='$type'>
                <p>
                    <strong>$message</strong>
                </p>
                <p>
                    $subMesssage                
                </p>
            </div>
         ";
    }
}
