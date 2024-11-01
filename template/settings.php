<?php

if (!defined('ABSPATH')) {
    exit; // Exit if accessed directly
}

$forumPathError = "<span style='color: %s'>Forum path is %s</span>";
$forumPathArgs = wvsso_valid_bulletin_path()
    ? array(
        'color' => 'green',
        'message' => 'valid'
    )
    : array(
        'color' => 'red',
        'message' => 'invalid'
    );

$forumPathError = vsprintf($forumPathError, $forumPathArgs);
$profileBuilderVal = ('on' === get_option(WVSSO_PROFILE_BUILDER_INTEGRATE)) ? 'checked' : '';

$profileBuilderField = "
<p><br>
    <strong><input type='checkbox' %s name='" . WVSSO_PROFILE_BUILDER_INTEGRATE . "' " . $profileBuilderVal . " />Integrate with Profile Builder</strong>
    <br /><span class='description'>Create redirects from standard Wordpress login pages to profile builder pages (set these URLs on vBulletin SSO settings page)</span>
    <br /><span class='description'>%s</span>
</p>
";

$profileBuilderFieldVal = WVSSO_PROFILE_BUILDER_ACTIVE
    ? array(
        'disabled' => '',
        'message' => ''
    )
    : array(
        'disabled' => 'onclick="return false;"',
        'message' => 'To use this option, please install and activate Profile Builder plugin first.'
    );
$profileBuilderField = vsprintf($profileBuilderField, $profileBuilderFieldVal);

// Logging level
$currentLoggingLevel = get_option(WVSSO_OPTION_NAME_LOGGING_LEVEL, 'error');
$logPhpErrors = get_option(WVSSO_OPTION_NAME_LOG_PHP_ERRORS);
$loggingLevels = array(
    'critical',
    'error',
    'warning',
    'notice',
    'info',
    'debug',
);

$logFiles = glob(WVSSO_LOGGING_PATH . '/*.log');
$num = 0;

$scriptSrc = plugin_dir_url(dirname(__FILE__)) . "includes/assets/js/admin.js";

?>
<script src='<?= $scriptSrc ?>'></script>

<form name='form1' method='post' action=''>
    <input type='hidden' name='submit_options' value='1'>
    <h3>Forum settings</h3>
    <h4>Enter path to vBulletin forum</h4>
    <p>
        <input type='text' size='80' name='<?= WVSSO_FORUM_PATH_NAME ?>'
               value='<?= get_option(WVSSO_FORUM_PATH_NAME) ?>'/>
        <br/><span class='description'>Path to vBulletin forum, for example: <?= ABSPATH ?>forum</span>
        <br/> <?= $forumPathError ?>
    </p>
    <h3>Other settings</h3>
    <h4>Forbidden pages</h4>
    <p>
        <input type='text' size='80'
               name='<?= WVSSO_OPTION_NAME_FORBIDDEN_PAGES ?>'
               value='<?= htmlentities(get_option(WVSSO_OPTION_NAME_FORBIDDEN_PAGES)) ?>'/>

        <br/>
        <span class='description'>Specify forbidden pages to redirect user to home page,
            after user login/register separated by space
        </span>
    </p>
    <h4>Illegal User names and characters</h4>
    <p>
        <input type='text' size='80' name='<?= WVSSO_OPTION_NAME_ILLEGAL_CHARS ?>'
               value='<?= htmlentities(get_option(WVSSO_OPTION_NAME_ILLEGAL_CHARS)) ?>'/>

        <br/><span class='description'>Specify names or characters separated by space</span>
    </p>
    <?= $profileBuilderField . wp_nonce_field("wvsso_save_settings") ?>
    <!-- Logging block html -->
    <p>
        <label for='id_wvsso_logging_level'><strong>Logging Level: </strong></label>
        <select id='id_wvsso_logging_level' name=' <?=WVSSO_OPTION_NAME_LOGGING_LEVEL ?>'>
            <?php foreach ($loggingLevels as $level) : ?>
                <option value='<?= $level ?>'<?php selected($level, $currentLoggingLevel) ?>> <?= ucfirst($level) ?> </option>
            <?php endforeach; ?>
        </select>
    </p>
    <p>
        <label for="id_wvsso_logging_level"><strong>Logging php errors:</strong></label>
        <input type="checkbox" name="<?= WVSSO_OPTION_NAME_LOG_PHP_ERRORS ?>" <?php checked($logPhpErrors, 'on') ?>>
    </p>
    <!-- Logging block end html -->
    <div align='right'>
        <input type='submit' name='Submit' class='button-primary' value='Save Settings'/>
    </div>
</form>

<form name='logs_block_post_form' method='post' action=''>
    <h4>Logs</h4>
    <table>
        <tbody>
        <tr>
            <td>
                <?php if (extension_loaded('zip')) :?>
                <button class='wvssoLoggingFormButton' action='wvssoDownloadAll'>Download all</button>
                <?php endif; ?>
                <button class='wvssoLoggingFormButton' action='wvssoRemoveAll'>Remove all</button>
            </td>
        </tr>
        <?php foreach ($logFiles as $file) : ?>
            <?php
            $num++;
            $log = basename($file);
            $sizeOfFile = filesize($file);
            $filesize = number_format($sizeOfFile / 1024, 2, ',', ' ') . ' KB';
            if ($sizeOfFile > (1024 * 1000)) {
                $filesize = number_format($sizeOfFile / 1024 / 1024, 2, ',', ' ') . ' MB';
            }
            ?>
            <tr>
                <td><?php echo "$num. $log($filesize)" ?></td>
                <td>
                    <button class='wvssoLoggingFormButton' action='wvssoDownload' filename='<?=$log ?>'>Download</button>
                </td>
                <td>
                    <button class='wvssoLoggingFormButton' action='wvssoRemove' filename='<?=$log ?>'>Remove</button>
                </td>
            </tr>
        <?php endforeach; ?>
        </tbody>
    </table>
    <input type='hidden' name='wvssoLoggingForm' id='wvssoLoggingForm' value='post'>
    <input type='hidden' name='wvssoLoggingFormAction' id='wvssoLoggingFormAction' value=''>
    <input type='hidden' name='wvssoLoggingFormFilename' id='wvssoLoggingFormFilename' value=''>
</form>
