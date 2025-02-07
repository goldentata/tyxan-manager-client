<?php

add_filter( 'auto_update_plugin', 'tyxan_manager_disable_auto_updates_for_plugin', 10, 2 );
function tyxan_manager_disable_auto_updates_for_plugin( $update, $item ) {
        return false; 
}

?>
