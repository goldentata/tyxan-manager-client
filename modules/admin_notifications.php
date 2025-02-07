<?php

add_action('admin_head', function() {
    echo '<style>
        .notice, .updated, .error, .notice-error, .notice-warning {
            display: none !important;
        }
    </style>';
});
?>
