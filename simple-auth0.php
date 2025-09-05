<?php

/**
 * Plugin Name: Simple Auth0
 * Plugin URI: https://github.com/your-username/simple-auth0
 * Description: A WordPress plugin that integrates Auth0 authentication and can optionally replace the native WordPress login flow.
 * Version: 1.0.0
 * Author: David Gaitan
 * Author URI: https://dgaitan.dev
 * License: GPL v2 or later
 * License URI: https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain: simple-auth0
 * Domain Path: /languages
 * Requires at least: 6.4
 * Tested up to: 6.5
 * Requires PHP: 8.1
 * Network: false
 *
 * @package SimpleAuth0
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
define('SIMPLE_AUTH0_PLUGIN_BASENAME', plugin_basename(__FILE__));

// Check WordPress and PHP version requirements
if (version_compare(get_bloginfo('version'), '6.4', '<')) {
    add_action('admin_notices', function () {
        echo '<div class="notice notice-error"><p>';
        echo esc_html__('Simple Auth0 requires WordPress 6.4 or higher.', 'simple-auth0');
        echo '</p></div>';
    });
    return;
}

if (version_compare(PHP_VERSION, '8.1', '<')) {
    add_action('admin_notices', function () {
        echo '<div class="notice notice-error"><p>';
        echo esc_html__('Simple Auth0 requires PHP 8.1 or higher.', 'simple-auth0');
        echo '</p></div>';
    });
    return;
}

// Load Composer autoloader
if (file_exists(SIMPLE_AUTH0_PLUGIN_DIR . 'vendor/autoload.php')) {
    require_once SIMPLE_AUTH0_PLUGIN_DIR . 'vendor/autoload.php';
} else {
    add_action('admin_notices', function () {
        echo '<div class="notice notice-error"><p>';
        echo esc_html__('Simple Auth0 dependencies not found. Please run "composer install" in the plugin directory.', 'simple-auth0');
        echo '</p></div>';
    });
    return;
}

// Load the main plugin class
require_once SIMPLE_AUTH0_PLUGIN_DIR . 'includes/class-simple-auth0.php';

/**
 * Initialize the plugin
 */
function simple_auth0_init()
{
    return SimpleAuth0\Simple_Auth0::get_instance();
}

// Initialize the plugin
add_action('plugins_loaded', 'simple_auth0_init');

/**
 * Plugin activation hook
 */
register_activation_hook(__FILE__, function () {
    // Set default options - ensure Auth0 login is disabled by default
    $default_options = [
        'domain' => '',
        'client_id' => '',
        'client_secret' => '',
        'audience' => '',
        'redirect_uri' => home_url('/wp-json/simple-auth0/v1/callback'),
        'logout_redirect_uri' => '',
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

    // Flush rewrite rules to ensure REST API routes are registered
    flush_rewrite_rules();
});

/**
 * Plugin deactivation hook
 */
register_deactivation_hook(__FILE__, function () {
    // Ensure Auth0 login is disabled on deactivation (safety measure)
    $options = get_option('simple_auth0_options', []);
    if (!empty($options['enable_auth0_login'])) {
        $options['enable_auth0_login'] = false;
        update_option('simple_auth0_options', $options);
    }

    // Flush rewrite rules to clean up REST API routes
    flush_rewrite_rules();

    // Note: We don't remove options on deactivation to preserve settings
    // This ensures users can reactivate without losing their configuration
});

/**
 * Plugin uninstall hook
 */
register_uninstall_hook(__FILE__, 'simple_auth0_uninstall');

/**
 * Plugin uninstall function
 */
function simple_auth0_uninstall() {
    // Remove plugin options if user chooses to do so
    // This will be handled by the admin interface
    // For now, we'll leave options intact to preserve user data
}
