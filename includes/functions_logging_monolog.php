<?php

if (!defined('ABSPATH')) {
    exit; // Exit if accessed directly  
}
require_once dirname(__FILE__) . '/../vendor/autoload.php';

define('WVSSO_UPDATE_USER_ERROR_TEXT', 'Attempt to update email or password of nonexistent user. Email: %s');
define('WVSSO_DELETE_USER_ERROR_TEXT', 'Attempt to delete nonexistent user. Email: %s');
define('WVSSO_DELETE_USER_UNKNOWN_ERROR_TEXT', 'Can not delete the user. Please do it manually. Email: %s');
define('WVSSO_LOGIN_USER_ERROR_TEXT', 'Attempt to log user into vBulletin failed. User with email: %s does not exist');
define('WVSSO_ACTIVATE_USER_ERROR_TEXT', 'Attempt to activate nonexistent user. Email: %s');
define('WVSSO_LOAD_USER_ERROR_TEXT',
    'Attempt to load user from vBulletin failed. User does not exist on vBulletin side. Email: %s');
define('WVSSO_SAVE_USER_ERROR_TEXT', 'Attempt to save userdata failed.');
define('WVSSO_USERNAME_DISCREPANCY_ERROR_TEXT',
    'There is a discrepancy with the username. Action: "%s"; wp_username: "%s", vb_username: "%s"');

/**
 * Writes message to a log file
 *
 * @staticvar Logger $localFileLogger
 *
 * @param string $level log level. debug, trace, info, error, warn. `Error` by default
 * @param string $message
 *
 * @return void
 */
function wvsso_log_message($level, $message)
{
    static $logger;

    if (!$logger) {
        $logger = new Monolog\Logger('wvsso');
        $logName = WVSSO_LOGGING_PATH . '/' . sprintf("wvsso_%s.log", date('Y-m-d'));
        $loggingLevel = get_option(WVSSO_OPTION_NAME_LOGGING_LEVEL);
        switch ($loggingLevel) {
            case '':
                break;
            case 'critical':
                $logLevel = Monolog\Logger::CRITICAL;
                break;
            case 'error':
                $logLevel = Monolog\Logger::ERROR;
                break;
            case 'warning':
                $logLevel = Monolog\Logger::WARNING;
                break;
            case 'notice':
                $logLevel = Monolog\Logger::NOTICE;
                break;
            case 'info':
                $logLevel = Monolog\Logger::INFO;
                break;
            case 'debug':
                $logLevel = Monolog\Logger::DEBUG;
                break;
            default:
                $logLevel = Monolog\Logger::ERROR;
                break;

        }
        $streamHandler = new \Monolog\Handler\StreamHandler($logName, $logLevel);
        $logger->pushHandler($streamHandler);
        $logger->pushHandler(new \Monolog\Handler\FirePHPHandler());
    }
    $logger->$level($message);
}

function wvsso_log_debug($message)
{
    wvsso_log_message('debug', $message);
}

function wvsso_log_info($message)
{
    wvsso_log_message('info', $message);
}

function wvsso_log_warning($message)
{
    wvsso_log_message('warning', $message);
}

function wvsso_log_error($message)
{
    wvsso_log_message('error', $message);
}

function wvsso_log_critical($message)
{
    wvsso_log_message('critical', $message);
}

function wvsso_shutdown_log()
{
    $lastError = error_get_last();

    if (!$lastError) {
        return;
    }
    $errorType = $lastError['type'];
    $message = " Type: {$errorType}, message: {$lastError['message']},"
        . " file: {$lastError['file']} , line: {$lastError['line']}";

    if ($errorType == E_ERROR) {
        wvsso_log_critical($message);
        return;
    }
    wvsso_log_warning($message);
}