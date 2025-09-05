<?php

/**
 * Simple Auth0 Plugin Class
 *
 * @package SimpleAuth0
 */

namespace SimpleAuth0;

if (!defined('ABSPATH')) {
    exit;
}

/**
 * Main plugin class
 */
class Simple_Auth0
{
    /**
     * Plugin instance
     *
     * @var Simple_Auth0
     */
    private static $instance = null;

    /**
     * Plugin options
     *
     * @var array
     */
    private $options = [];

    /**
     * Get plugin instance
     *
     * @return Simple_Auth0
     */
    public static function get_instance()
    {
        if (null === self::$instance) {
            self::$instance = new self();
        }
        return self::$instance;
    }

    /**
     * Constructor
     */
    private function __construct()
    {
        $this->load_options();
        $this->init_hooks();
    }

    /**
     * Initialize hooks
     */
    private function init_hooks()
    {
        if (is_admin()) {
            add_action('admin_menu', [$this, 'add_admin_menu']);
            add_action('admin_init', [$this, 'admin_init']);
            add_action('admin_enqueue_scripts', [$this, 'enqueue_admin_scripts']);
        }
    }

    /**
     * Load plugin options
     */
    private function load_options()
    {
        $this->options = get_option('simple_auth0_options', []);
    }

    /**
     * Add admin menu
     */
    public function add_admin_menu()
    {
        add_options_page(
            __('Simple Auth0', 'simple-auth0'),
            __('Simple Auth0', 'simple-auth0'),
            'manage_options',
            'simple-auth0',
            [$this, 'admin_page']
        );
    }

    /**
     * Admin init
     */
    public function admin_init()
    {
        register_setting('simple_auth0_options', 'simple_auth0_options', [
            'sanitize_callback' => [$this, 'sanitize_options']
        ]);

        // AJAX handlers
        add_action('wp_ajax_simple_auth0_test_connection', [$this, 'ajax_test_connection']);
        add_action('wp_ajax_simple_auth0_preview_export', [$this, 'ajax_preview_export']);
        add_action('wp_ajax_simple_auth0_download_export', [$this, 'ajax_download_export']);
    }

    /**
     * Sanitize options
     *
     * @param array $input Input options
     * @return array Sanitized options
     */
    public function sanitize_options($input)
    {
        $sanitized = [];

        // Domain
        if (!empty($input['domain'])) {
            $sanitized['domain'] = sanitize_text_field($input['domain']);
        }

        // Client ID
        if (!empty($input['client_id'])) {
            $sanitized['client_id'] = sanitize_text_field($input['client_id']);
        }

        // Client Secret (only update if not empty)
        if (!empty($input['client_secret'])) {
            $sanitized['client_secret'] = sanitize_text_field($input['client_secret']);
        } else {
            $sanitized['client_secret'] = $this->options['client_secret'] ?? '';
        }

        // Redirect URI
        $sanitized['redirect_uri'] = !empty($input['redirect_uri'])
            ? esc_url_raw($input['redirect_uri'])
            : home_url('/wp-json/simple-auth0/v1/callback');

        // Scopes
        $sanitized['scopes'] = !empty($input['scopes'])
            ? sanitize_text_field($input['scopes'])
            : 'openid profile email';

        // Audience (optional)
        $sanitized['audience'] = !empty($input['audience'])
            ? sanitize_text_field($input['audience'])
            : '';

        // Enable Auth0 Login
        $sanitized['enable_auth0_login'] = !empty($input['enable_auth0_login']);

        // Auto sync users
        $sanitized['auto_sync_users'] = !empty($input['auto_sync_users']);

        // Export hash algorithm
        $sanitized['export_hash_algorithm'] = !empty($input['export_hash_algorithm'])
            ? sanitize_text_field($input['export_hash_algorithm'])
            : '';

        // Status tracking
        $sanitized['status_last_checked'] = $this->options['status_last_checked'] ?? 0;
        $sanitized['status_ok'] = $this->options['status_ok'] ?? false;

        return $sanitized;
    }

    /**
     * Enqueue admin scripts and styles
     */
    public function enqueue_admin_scripts($hook)
    {
        // Only load on our admin page
        if ('settings_page_simple-auth0' !== $hook) {
            return;
        }

        // Enqueue external CSS
        wp_enqueue_style(
            'simple-auth0-admin',
            plugin_dir_url(__FILE__) . '../admin/css/admin.css',
            [],
            '1.0.0'
        );

        // Enqueue external JavaScript
        wp_enqueue_script(
            'simple-auth0-admin',
            plugin_dir_url(__FILE__) . '../admin/js/admin.js',
            ['jquery'],
            '1.0.0',
            true
        );

        // Localize script for AJAX
        wp_localize_script('simple-auth0-admin', 'simple_auth0_admin', [
            'ajax_url' => admin_url('admin-ajax.php'),
            'nonce' => wp_create_nonce('simple_auth0_admin_nonce')
        ]);
    }

    /**
     * Render admin page using template
     */
    public function admin_page()
    {
        $current_tab = $_GET['tab'] ?? 'settings';
        $tabs = [
            'settings' => __('Settings', 'simple-auth0'),
            'sync' => __('Sync', 'simple-auth0'),
            'help' => __('Help', 'simple-auth0'),
        ];

        // Get tab content
        $tab_content = $this->get_tab_content($current_tab);

        // Load template
        $template_vars = [
            'page_title' => get_admin_page_title(),
            'tabs' => $tabs,
            'current_tab' => $current_tab,
            'tab_content' => $tab_content
        ];

        $this->load_template('admin-page.php', $template_vars);
    }

    /**
     * Get content for specific tab
     */
    private function get_tab_content($tab)
    {
        ob_start();

        switch ($tab) {
            case 'settings':
                $this->load_template('settings-tab.php', ['options' => $this->options]);
                break;
            case 'sync':
                $this->load_template('sync-tab.php');
                break;
            case 'help':
                $this->load_template('help-tab.php');
                break;
            default:
                $this->load_template('settings-tab.php', ['options' => $this->options]);
        }

        return ob_get_clean();
    }

    /**
     * Load template file
     */
    private function load_template($template_name, $vars = [])
    {
        $template_path = plugin_dir_path(__FILE__) . '../admin/templates/' . $template_name;

        if (file_exists($template_path)) {
            extract($vars);
            include $template_path;
        } else {
            echo '<p>' . sprintf(__('Template not found: %s', 'simple-auth0'), $template_name) . '</p>';
        }
    }

    /**
     * AJAX handler for testing connection
     */
    public function ajax_test_connection()
    {
        // Verify nonce
        if (!wp_verify_nonce($_POST['nonce'], 'simple_auth0_admin_nonce')) {
            wp_send_json_error(['message' => __('Security check failed', 'simple-auth0')]);
        }

        // Check capabilities
        if (!current_user_can('manage_options')) {
            wp_send_json_error(['message' => __('Insufficient permissions', 'simple-auth0')]);
        }

        $result = $this->test_auth0_connection($this->options);

        if ($result['success']) {
            wp_send_json_success(['message' => $result['message']]);
        } else {
            wp_send_json_error(['message' => $result['message']]);
        }
    }

    /**
     * Test Auth0 connection
     */
    private function test_auth0_connection($options)
    {
        if (empty($options['domain'])) {
            return ['success' => false, 'message' => __('Auth0 domain is required', 'simple-auth0')];
        }

        if (empty($options['client_id'])) {
            return ['success' => false, 'message' => __('Client ID is required', 'simple-auth0')];
        }

        // Validate domain format
        if (!preg_match('/^[a-zA-Z0-9][a-zA-Z0-9-]*[a-zA-Z0-9]*\.auth0\.com$/', $options['domain'])) {
            return ['success' => false, 'message' => __('Invalid Auth0 domain format', 'simple-auth0')];
        }

        // Test connection by fetching well-known configuration
        $well_known_url = 'https://' . $options['domain'] . '/.well-known/openid_configuration';

        $response = wp_remote_get($well_known_url, [
            'timeout' => 10,
            'headers' => [
                'User-Agent' => 'Simple Auth0 WordPress Plugin'
            ]
        ]);

        if (is_wp_error($response)) {
            return ['success' => false, 'message' => __('Network error: ' . $response->get_error_message(), 'simple-auth0')];
        }

        $response_code = wp_remote_retrieve_response_code($response);
        if ($response_code !== 200) {
            return ['success' => false, 'message' => sprintf(__('Auth0 service error (HTTP %d)', 'simple-auth0'), $response_code)];
        }

        $body = wp_remote_retrieve_body($response);
        $config = json_decode($body, true);

        if (!$config || !isset($config['issuer'])) {
            return ['success' => false, 'message' => __('Invalid Auth0 configuration response', 'simple-auth0')];
        }

        // Update status
        $this->options['status_last_checked'] = time();
        $this->options['status_ok'] = true;
        update_option('simple_auth0_options', $this->options);

        return ['success' => true, 'message' => __('Successfully connected to Auth0', 'simple-auth0')];
    }

    /**
     * AJAX handler for preview export
     */
    public function ajax_preview_export()
    {
        // Verify nonce
        if (!wp_verify_nonce($_POST['nonce'], 'simple_auth0_admin_nonce')) {
            wp_send_json_error(['message' => __('Security check failed', 'simple-auth0')]);
        }

        // Check capabilities
        if (!current_user_can('manage_options')) {
            wp_send_json_error(['message' => __('Insufficient permissions', 'simple-auth0')]);
        }

        $users = $this->get_users_for_export(5); // Preview first 5 users
        wp_send_json_success($users);
    }

    /**
     * AJAX handler for download export
     */
    public function ajax_download_export()
    {
        // Verify nonce
        if (!wp_verify_nonce($_POST['nonce'], 'simple_auth0_admin_nonce')) {
            wp_send_json_error(['message' => __('Security check failed', 'simple-auth0')]);
        }

        // Check capabilities
        if (!current_user_can('manage_options')) {
            wp_send_json_error(['message' => __('Insufficient permissions', 'simple-auth0')]);
        }

        $users = $this->get_users_for_export();
        wp_send_json_success($users);
    }

    /**
     * Get users for export
     */
    private function get_users_for_export($limit = null)
    {
        $args = [
            'number' => $limit,
            'orderby' => 'ID',
            'order' => 'ASC'
        ];

        $users = get_users($args);
        $export_data = [];

        foreach ($users as $user) {
            $export_data[] = [
                'email' => $user->user_email,
                'email_verified' => true, // Best effort
                'user_id' => 'wp|' . $user->ID,
                'name' => $user->display_name,
                'nickname' => $user->user_nicename,
                'created_at' => $user->user_registered,
                'updated_at' => $user->user_registered
            ];
        }

        return $export_data;
    }
}
