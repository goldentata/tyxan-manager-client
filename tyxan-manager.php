<?php
/**
 * Plugin Name: Tyxan Manager
 * Description: 
 * Version: 1.0.1
 * Author: Tyxan Team
 * Text Domain: wp-remote-manager
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit; // Exit if accessed directly
}



require_once('modules/admin_notifications.php');
require_once('modules/auto_updates_disabled.php');



// wp rest endpoints
add_action('rest_api_init', function() {

    // Ping - check if connection is still live from the manager POV
    register_rest_route('tyxan-manager/v1', '/ping', [
        'methods'  => 'GET',
        'callback' => 'tyxan_manager_ping',
        'permission_callback' => '__return_true',
    ]);

    // Update
    register_rest_route('tyxan-manager/v1', '/update', [
        'methods'  => 'POST',
        'callback' => 'tyxan_manager_update_plugin',
        'permission_callback' => '__return_true',
    ]);

    // Generate one-click login link
    register_rest_route('tyxan-manager/v1', '/login-link', [
        'methods'  => 'POST',
        'callback' => 'tyxan_manager_login_link',
        'permission_callback' => '__return_true',
    ]);
});

// response for pings
function tyxan_manager_ping() {
    return ['status' => 'ok', 'message' => 'Long live the empire!'];
}

// handler for downloading a new version of the plugin
function tyxan_manager_update_plugin($request) {
   $manager_secret = get_option('tyxan_manager_secret', '');
    if ($request->get_param('api_key') != $manager_secret) {
        return new WP_Error('invalid_api_key', 'Invalid API key', ['status' => 403]);
    }

    $zipUrl = $request->get_param('zip_url');
    if (empty($zipUrl)) {
        return new WP_Error('missing_param', 'zip_url is required', ['status' => 400]);
    }

  
    $response = download_url($zipUrl);
    if (is_wp_error($response)) {
        return new WP_Error('download_error', $response->get_error_message(), ['status' => 500]);
    }

    
    $result = unzip_file($response, WP_PLUGIN_DIR);
    @unlink($response); 

    if (is_wp_error($result)) {
        return new WP_Error('unzip_error', $result->get_error_message(), ['status' => 500]);
    }

    // reactivate the plugin in case we have some things to be hooked
    activate_plugin('tyxan-manager/tyxan-manager.php');

    return ['status' => 'updated', 'message' => 'Plugin updated successfully'];
}

// one click sign in
function tyxan_manager_login_link($request) {
    $apiKey = $request->get_param('api_key');
    $manager_secret = get_option('tyxan_manager_secret', '');
    if ($apiKey != $manager_secret) {
        return new WP_Error('invalid_api_key', 'Invalid API key', ['status' => 403]);
    }

    // let's assume user ID 1 is the admin
    $userId = 1;

    $token = wp_generate_uuid4();
    $expires = time() + 60; 

    update_user_meta($userId, '_remote_login_token', [
        'token' => $token,
        'expires_at' => $expires,
    ]);

    $loginUrl = add_query_arg(['remote_login' => $token], site_url());

    return [
        'status' => 'ok',
        'login_url' => $loginUrl
    ];
}


// make wordpress understand our remote_login token
add_action('init', function() {
    if (isset($_GET['remote_login'])) {
        $token = sanitize_text_field($_GET['remote_login']);
        if (empty($token)) return;

        // log in as user id 1
        $userId = 1;
        $stored = get_user_meta($userId, '_remote_login_token', true);

        if (! is_array($stored) || ! isset($stored['token'])) {
            return;
        }

        if ($stored['token'] === $token && time() < $stored['expires_at']) {
            wp_set_auth_cookie($userId, true, is_ssl());
            delete_user_meta($userId, '_remote_login_token');

            wp_safe_redirect(admin_url());
            exit;
        }
    }
});

// register the site in manager on plugin activation
register_activation_hook(__FILE__, 'tyxan_manager_on_activation');
function tyxan_manager_on_activation() {
    $manager_url = rtrim(get_option('tyxan_manager_url', ''), '/');

   $manager_secret = get_option('tyxan_manager_secret', '');
    
    $body = [
        'site_url'  => get_site_url(),
        'site_name' => get_bloginfo('name'),
        'api_key'   => $manager_secret, 
    ];

    $response = wp_remote_post($manager_url . '/register.php', [
        'body'      => $body,
        'timeout'   => 20,
        'sslverify' => true,
    ]);

    if (is_wp_error($response)) {
        error_log('Tyxan Manager registration failed: ' . $response->get_error_message());
    }
}

// remove website from our manager on plugin deactivation
register_deactivation_hook(__FILE__, 'tyxan_manager_on_deactivation');
function tyxan_manager_on_deactivation() {
    $manager_url = rtrim(get_option('tyxan_manager_url', ''), '/');
    
   $manager_secret = get_option('tyxan_manager_secret', '');

    $body = [
        'site_url' => get_site_url(),
        'api_key'  => $manager_secret,
    ];

    $response = wp_remote_post($manager_url . '/unregister.php', [
        'body'      => $body,
        'timeout'   => 20,
        'sslverify' => true,
    ]);

    if (is_wp_error($response)) {
        error_log('Tyxan Manager deregistration failed: ' . $response->get_error_message());
    }
}

function tyxan_manager_register_site() {
    $manager_url = rtrim(get_option('tyxan_manager_url', ''), '/');

   $manager_secret = get_option('tyxan_manager_secret', '');
    $body = [
        'site_url'  => get_site_url(),
        'site_name' => get_bloginfo('name'),
        'api_key'   => $manager_secret,
    ];

    $response = wp_remote_post($manager_url . '/register.php', [
        'body'      => $body,
        'timeout'   => 20,
        'sslverify' => true,
    ]);

    if (is_wp_error($response)) {
        $error_message = $response->get_error_message();
        update_option('tyxan_manager_last_status','Connection failed: ' . $error_message);
        error_log('Tyxan Manager registration failed: ' . $error_message);
    } else {
        $code     = wp_remote_retrieve_response_code($response);
        $res_body = wp_remote_retrieve_body($response);

        if ($code == 200) {
            update_option('tyxan_manager_last_status','Connection successful. Server Response: ' . $res_body);
        } else {
            update_option('tyxan_manager_last_status',"Connection failed (HTTP $code). Response: $res_body");
            error_log("Tyxan Manager registration failed (HTTP $code). Response: $res_body");
        }
    }
}



add_action('admin_menu', 'tyxan_manager_add_menu_page');
function tyxan_manager_add_menu_page() {
    add_menu_page(
        'Tyxan Manager',
        'Tyxan Manager',
        'manage_options',
        'tyxan-manager',
        'tyxan_manager_status_page'
    );
}


function tyxan_manager_status_page() {
    if (!current_user_can('manage_options')) {
        wp_die(__('You do not have permission to access this page.'));
    }

    $status = get_option('tyxan_manager_last_status', 'No connection attempt yet.');
    ?>
    <div class="wrap">
        <h1>Tyxan Manager Status</h1>
        <p><strong>Last Connection Status:</strong> <?php echo esc_html($status); ?></p>

        <form method="post" action="<?php echo esc_url(admin_url('admin-post.php')); ?>">
            <?php wp_nonce_field('tyxan_manager_reconnect'); ?>
            <input type="hidden" name="action" value="tyxan_manager_reconnect">
            <button type="submit" class="button button-primary">Reconnect</button>
        </form>
    </div>
    <?php
}


add_action('admin_post_tyxan_manager_reconnect', 'tyxan_manager_handle_reconnect');
function tyxan_manager_handle_reconnect() {
    if (!current_user_can('manage_options')) {
        wp_die(__('You do not have permission to do that.'));
    }

    check_admin_referer('tyxan_manager_reconnect');

    tyxan_manager_register_site();

    wp_redirect(admin_url('admin.php?page=tyxan-manager'));
    exit;
}

add_action('admin_init', 'tyxan_manager_register_settings');
function tyxan_manager_register_settings() {
    register_setting('tyxan_manager_settings_group', 'tyxan_manager_secret');
    register_setting('tyxan_manager_settings_group', 'tyxan_manager_url');
}


// heartbeat experiments - buggy - periodically re-register the site
/*
add_action('wp', 'wp_remote_manager_schedule_heartbeat');
function wp_remote_manager_schedule_heartbeat() {
    if (!wp_next_scheduled('wp_remote_manager_daily_heartbeat')) {
        wp_schedule_event(time(), 'daily', 'wp_remote_manager_daily_heartbeat');
    }
}

add_action('wp_remote_manager_daily_heartbeat', 'wp_remote_manager_send_heartbeat');
function wp_remote_manager_send_heartbeat() {
    $url = WP_REMOTE_MANAGER_URL . '/register.php'; 
    $body = [
        'site_url'  => get_site_url(),
        'site_name' => get_bloginfo('name'),
        'api_key'   => WP_REMOTE_MANAGER_SECRET,
    ];

    wp_remote_post($url, [
        'body'      => $body,
        'timeout'   => 20,
        'sslverify' => true,
    ]);
}
*/
