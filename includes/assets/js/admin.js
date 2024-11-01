jQuery(document).ready(function () {
    jQuery('.wvssoLoggingFormButton').click(function () {
        jQuery('#wvssoLoggingFormFilename').val(jQuery(this).attr('filename'));
        jQuery('#wvssoLoggingFormAction').val(jQuery(this).attr('action'));
        jQuery('#wvssoLoggingForm').submit();
    });
});
