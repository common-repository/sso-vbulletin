<?php

namespace com\extremeidea\wordpress\wordpress\vbulletin\sso;

if (!defined('ABSPATH')) {
    exit; // Exit if accessed directly
}

class ManageLogFiles
{

    public function downloadLog($file)
    {
        header('Content-Description: File Transfer');
        header('Content-Type: text/plain');
        header('Content-Disposition: attachment; filename="' . basename($file) . '";');
        header('Content-Transfer-Encoding: binary');
        header('Content-Length: ' . filesize($file));
        if (ob_get_contents()) {
            ob_clean();
        }
        readfile($file);
        exit();
    }

    public function downloadAllLogs()
    {
        $files = glob(WVSSO_LOGGING_PATH . '/*.log');
        $zip = get_temp_dir() . 'wvsso-logs.zip';
        $this->compressFiles($files, $zip);
        $this->downloadLog($zip);
        unlink($zip);
    }

    protected function compressFiles($files, $destination)
    {
        $zip = new \ZipArchive();

        if (!$zip->open($destination, \ZipArchive::CREATE | \ZipArchive::OVERWRITE)) {
            $this->logError('Unable to create zip destination: ' . $destination);
            return false;
        }
        $errors = 0;
        if (!count($files)) {
            $zip->addFromString('.empty', '');
        }
        foreach ($files as $file) {
            if (!$zip->addFile($file, basename($file))) {
                wvsso_log_error('Unable to add file to zip: ' . $file['file']);
                $errors += 1;
            }
        }

        if (!$zip->close()) {
            wvsso_log_error('Unable to close destination file: ' . $destination);
            $errors += 1;
        }
        return true && !$errors;
    }

    public function removeAllLogs()
    {
        array_map('unlink', glob(WVSSO_LOGGING_PATH . '/*.log'));
    }

    public function removeLog($file)
    {
        unlink($file);
    }
}