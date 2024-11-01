<?php

if (!defined('ABSPATH')) {
    exit; // Exit if accessed directly  
}

get_header('home');

echo "
     <div>
        <h2>
        " . WVSSO_RESET_PASSWORD_REQUIRED_MESSAGE . "
        </h2>
     </div>
     ";

get_footer('home');
