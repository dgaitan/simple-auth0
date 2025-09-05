<?php

/**
 * Plugin Name: Simple Auth0
 * Plugin URI: https://github.com/your-username/simple-auth0
 * Description: A WordPress plugin that integrates with Auth0 for authentication.
 * Version: 1.0.0
 * Author: Your Name
 * License: GPL v2 or later
 * Text Domain: simple-auth0
 * Domain Path: /languages
 */

// Prevent direct access
if (!defined('ABSPATH')) {
    exit;
}

// Define plugin constants
define('SIMPLE_AUTH0_VERSION', '1.0.0');
define('SIMPLE_AUTH0_PLUGIN_FILE', __FILE__);
define('SIMPLE_AUTH0_PLUGIN_DIR', plugin_dir_path(__FILE__));
define('SIMPLE_AUTH0_PLUGIN_URL', plugin_dir_url(__FILE__));

/**
 * Plugin activation hook
 */
register_activation_hook(__FILE__, function () {
    $default_options = [
        'domain' => '',
        'client_id' => '',
        'client_secret' => '',
        'audience' => '',
        'redirect_uri' => home_url('/wp-json/simple-auth0/v1/callback'),
        'logout_redirect_uri' => home_url(),
        'scopes' => 'openid profile email',
        'enable_auth0_login' => false, // CRITICAL: Must be false by default
        'auto_sync_users' => true,
        'export_hash_algorithm' => '',
        'status_last_checked' => 0,
        'status_ok' => false,
    ];

    // Only add options if they don't exist (preserve existing settings on reactivation)
    if (!get_option('simple_auth0_options')) {
        add_option('simple_auth0_options', $default_options, '', 'no');
    } else {
        // Ensure enable_auth0_login is false on reactivation (safety measure)
        $existing_options = get_option('simple_auth0_options', []);
        $existing_options['enable_auth0_login'] = false;
        update_option('simple_auth0_options', $existing_options);
    }
});

/**
 * Plugin deactivation hook
 */
register_deactivation_hook(__FILE__, function () {
    $options = get_option('simple_auth0_options', []);
    if (!empty($options['enable_auth0_login'])) {
        $options['enable_auth0_login'] = false;
        update_option('simple_auth0_options', $options);
    }
});

/**
 * Plugin uninstall hook
 */
register_uninstall_hook(__FILE__, 'simple_auth0_uninstall');

function simple_auth0_uninstall()
{
    // Remove plugin options if user chooses to do so
    // This will be handled by the admin interface
    // For now, we'll leave options intact to preserve user data
}

/**
 * Initialize the plugin
 */
function simple_auth0_init()
{
    // Load the main plugin class
    require_once SIMPLE_AUTH0_PLUGIN_DIR . 'includes/class-simple-auth0.php';

    return SimpleAuth0\Simple_Auth0::get_instance();
}

// Initialize the plugin
add_action('plugins_loaded', 'simple_auth0_init');
