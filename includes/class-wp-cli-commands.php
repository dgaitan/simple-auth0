<?php
/**
 * WP-CLI commands for Simple Auth0
 *
 * @package SimpleAuth0
 */

namespace SimpleAuth0;

// Prevent direct access
if (!defined('ABSPATH')) {
    exit;
}

// Only load if WP-CLI is available
if (!defined('WP_CLI') || !WP_CLI) {
    return;
}

/**
 * WP-CLI commands class
 */
class WP_CLI_Commands {

    /**
     * Test Story #1: Install without takeover
     *
     * ## EXAMPLES
     *
     *     wp simple-auth0 test-story1
     *
     * @when after_wp_load
     */
    public function test_story1() {
        require_once SIMPLE_AUTH0_PLUGIN_DIR . 'tests/test-story1.php';
        
        $test = new \Test_Story1();
        $success = $test->run_all_tests();
        
        if ($success) {
            \WP_CLI::success('Story #1 tests completed successfully!');
        } else {
            \WP_CLI::error('Story #1 tests failed!');
        }
    }

    /**
     * Check plugin status
     *
     * ## EXAMPLES
     *
     *     wp simple-auth0 status
     *
     * @when after_wp_load
     */
    public function status() {
        $plugin = Simple_Auth0::get_instance();
        $options = $plugin->get_options();
        
        \WP_CLI::line('Simple Auth0 Plugin Status:');
        \WP_CLI::line('');
        
        // Connection status
        $enabled = $plugin->is_auth0_login_enabled();
        $status = $enabled ? 'Enabled' : 'Disabled';
        $color = $enabled ? 'green' : 'yellow';
        
        \WP_CLI::line("Auth0 Login: " . \WP_CLI::colorize("%{$color}%{$status}%n"));
        
        // Configuration status
        $configured = !empty($options['domain']) && !empty($options['client_id']);
        $config_status = $configured ? 'Configured' : 'Not Configured';
        $config_color = $configured ? 'green' : 'red';
        
        \WP_CLI::line("Configuration: " . \WP_CLI::colorize("%{$config_color}%{$config_status}%n"));
        
        // Key settings
        if ($configured) {
            \WP_CLI::line('');
            \WP_CLI::line('Configuration Details:');
            \WP_CLI::line("  Domain: {$options['domain']}");
            \WP_CLI::line("  Client ID: {$options['client_id']}");
            \WP_CLI::line("  Redirect URI: {$options['redirect_uri']}");
            \WP_CLI::line("  Scopes: {$options['scopes']}");
        }
    }

    /**
     * Reset plugin to default state
     *
     * ## EXAMPLES
     *
     *     wp simple-auth0 reset
     *
     * @when after_wp_load
     */
    public function reset() {
        $default_options = [
            'domain' => '',
            'client_id' => '',
            'client_secret' => '',
            'audience' => '',
            'redirect_uri' => home_url('/wp-json/simple-auth0/v1/callback'),
            'logout_redirect_uri' => '',
            'scopes' => 'openid profile email',
            'enable_auth0_login' => false,
            'auto_sync_users' => true,
            'export_hash_algorithm' => '',
            'status_last_checked' => 0,
            'status_ok' => false,
        ];
        
        update_option('simple_auth0_options', $default_options);
        
        \WP_CLI::success('Plugin reset to default state');
        \WP_CLI::line('Auth0 login is now disabled');
    }
}

// Register WP-CLI commands
\WP_CLI::add_command('simple-auth0', 'SimpleAuth0\WP_CLI_Commands');
