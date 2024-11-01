jQuery(document).ready(function () {

    //Show warning: Password should not be equal to username.
    var username_li = jQuery('.wppb-default-username');
    var pass_li = jQuery('.wppb-default-password');
    var pass_input = jQuery('#passw1');
    var username_input = jQuery('#username');
    var pass_username_warn_text = 'Password should not be equal to username.';
    var pass_username_error_id = 'pass-username-error';
    var li_field_error_class = 'wppb-field-error';
    var field_success_class = 'wppb-success';
    var pass_username_span_error = '<span class="wppb-form-error" id="' + pass_username_error_id + '">' + pass_username_warn_text + '</span>';

    username_input.blur(function (event) {
        wvsso_pass_username_handle_warning();
    });

    pass_input.blur(function (event) {
        wvsso_pass_username_handle_warning();
    });

    function wvsso_pass_username_handle_warning() {
        if (pass_input.val() === username_input.val() && username_input.val()) {
            wvsso_pass_username_show_warning();
        } else {
            wvsso_pass_username_clean_warning();
        }
    }
    function wvsso_pass_username_clean_warning() {
        if (document.getElementById(pass_username_error_id)) {
            pass_li.removeClass(li_field_error_class);
            document.getElementById(pass_username_error_id).remove();
        }
    }

    function wvsso_pass_username_show_warning() {
        if (!document.getElementById(pass_username_error_id) && !jQuery('.wppb-default-password .wppb-form-error')) {
            pass_li.addClass(li_field_error_class);
            pass_input.after(pass_username_span_error);
        }
    }

    /*AJAX: Check is username available for registration*/
    username_input.change(function (event) {
        username_li.removeClass(li_field_error_class);
        username_li.removeClass(field_success_class);
        jQuery('.wppb-default-username > span').remove();

        jQuery.ajax({
            type: "POST",
            url: wvsso_ajax['url'],
            data: {
                action: 'wvsso_check_login',
                username: username_input.val()
            },
            success: function (server_response) {
                response = jQuery.parseJSON(server_response);

                username_input.after('<span>' + response.msg + '</span>');

                if (response.status == 'ok') {
                    username_li.addClass(field_success_class);
                } else {
                    username_li.addClass(li_field_error_class);
                }
            }
        });
    });


});

