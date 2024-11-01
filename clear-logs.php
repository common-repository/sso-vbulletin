<?php

if (!defined('ABSPATH')) {
    exit; // Exit if accessed directly  
}

require_once(dirname(__FILE__) . '/config.php');

$logfiles = glob(WVSSO_LOGGING_PATH . '/*.log');
$now = time();
$year = 60 * 60 * 24 * 365;

foreach ($logfiles as $value) {

    preg_match('|[\d]{4}-[\d]{2}|', basename($value), $matches);

    if (isset($matches[0])) {
        if ($now - strtotime($matches[0]) > $year) {
            unlink($value);
        }
    }
}
