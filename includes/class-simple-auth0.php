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
            add_action('wp_ajax_simple_auth0_test_connection', [$this, 'ajax_test_connection']);
        }

        // Auth0 login hooks
        add_action('login_init', [$this, 'maybe_redirect_to_auth0']);
        add_action('wp_logout', [$this, 'handle_logout']);
        add_filter('login_url', [$this, 'filter_login_url'], 10, 2);
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
     * Sanitize options with enhanced validation
     *
     * @param array $input Input options
     * @return array Sanitized options
     */
    public function sanitize_options($input)
    {
        $sanitized = [];
        $errors = [];

        // Domain validation
        if (!empty($input['domain'])) {
            $domain = sanitize_text_field($input['domain']);
            if ($this->validate_auth0_domain($domain)) {
                $sanitized['domain'] = $domain;
            } else {
                add_settings_error(
                    'simple_auth0_options',
                    'invalid_domain',
                    __('Please enter a valid Auth0 domain (e.g., your-tenant.auth0.com)', 'simple-auth0')
                );
                $sanitized['domain'] = $this->options['domain'] ?? '';
            }
        } else {
            $sanitized['domain'] = $this->options['domain'] ?? '';
        }

        // Client ID validation
        if (!empty($input['client_id'])) {
            $client_id = sanitize_text_field($input['client_id']);
            if (strlen($client_id) >= 10) { // Basic length check
                $sanitized['client_id'] = $client_id;
            } else {
                add_settings_error(
                    'simple_auth0_options',
                    'invalid_client_id',
                    __('Client ID must be at least 10 characters long', 'simple-auth0')
                );
                $sanitized['client_id'] = $this->options['client_id'] ?? '';
            }
        } else {
            $sanitized['client_id'] = $this->options['client_id'] ?? '';
        }

        // Client Secret (only update if not empty, with security)
        if (!empty($input['client_secret'])) {
            $client_secret = sanitize_text_field($input['client_secret']);
            if (strlen($client_secret) >= 20) { // Basic length check
                // Encrypt the client secret if possible
                $sanitized['client_secret'] = $this->encrypt_secret($client_secret);
            } else {
                add_settings_error(
                    'simple_auth0_options',
                    'invalid_client_secret',
                    __('Client Secret must be at least 20 characters long', 'simple-auth0')
                );
                $sanitized['client_secret'] = $this->options['client_secret'] ?? '';
            }
        } else {
            // Keep existing secret if field is empty
            $sanitized['client_secret'] = $this->options['client_secret'] ?? '';
        }

        // Redirect URI validation
        if (!empty($input['redirect_uri'])) {
            $redirect_uri = esc_url_raw($input['redirect_uri']);
            if ($this->validate_redirect_uri($redirect_uri)) {
                $sanitized['redirect_uri'] = $redirect_uri;
            } else {
                add_settings_error(
                    'simple_auth0_options',
                    'invalid_redirect_uri',
                    __('Redirect URI must be a valid URL on your current site', 'simple-auth0')
                );
                $sanitized['redirect_uri'] = $this->options['redirect_uri'] ?? home_url('/wp-json/simple-auth0/v1/callback');
            }
        } else {
            $sanitized['redirect_uri'] = home_url('/wp-json/simple-auth0/v1/callback');
        }

        // Scopes validation
        if (!empty($input['scopes'])) {
            $scopes = sanitize_text_field($input['scopes']);
            if ($this->validate_scopes($scopes)) {
                $sanitized['scopes'] = $scopes;
            } else {
                add_settings_error(
                    'simple_auth0_options',
                    'invalid_scopes',
                    __('Scopes must be space-separated and contain only valid OAuth scopes', 'simple-auth0')
                );
                $sanitized['scopes'] = $this->options['scopes'] ?? 'openid profile email';
            }
        } else {
            $sanitized['scopes'] = 'openid profile email';
        }

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

        // Status tracking - keep existing values, don't auto-test
        $sanitized['status_last_checked'] = $this->options['status_last_checked'] ?? 0;
        $sanitized['status_ok'] = $this->options['status_ok'] ?? false;

        return $sanitized;
    }

    /**
     * Validate Auth0 domain format
     *
     * @param string $domain Domain to validate
     * @return bool
     */
    private function validate_auth0_domain($domain)
    {
        // Auth0 domain pattern: more flexible to handle various Auth0 domain formats
        // Supports: tenant.auth0.com, tenant.us.auth0.com, tenant.eu.auth0.com, tenant.au.auth0.com
        // Also supports custom domains that end with .auth0.com
        $pattern = '/^[a-zA-Z0-9][a-zA-Z0-9-]*[a-zA-Z0-9]*\.(auth0\.com|us\.auth0\.com|eu\.auth0\.com|au\.auth0\.com|dev\.auth0\.com)$/';

        // Also allow domains that just end with .auth0.com (for custom domains)
        if (preg_match($pattern, $domain) === 1) {
            return true;
        }

        // Fallback: check if it ends with .auth0.com and has a reasonable format
        if (preg_match('/^[a-zA-Z0-9][a-zA-Z0-9-]*[a-zA-Z0-9]*\.auth0\.com$/', $domain) === 1) {
            return true;
        }

        return false;
    }

    /**
     * Validate redirect URI
     *
     * @param string $uri URI to validate
     * @return bool
     */
    private function validate_redirect_uri($uri)
    {
        // Must be a valid URL
        if (!filter_var($uri, FILTER_VALIDATE_URL)) {
            return false;
        }

        // Must be on the same domain as the current site
        $current_domain = parse_url(home_url(), PHP_URL_HOST);
        $uri_domain = parse_url($uri, PHP_URL_HOST);

        return $current_domain === $uri_domain;
    }

    /**
     * Validate OAuth scopes
     *
     * @param string $scopes Scopes to validate
     * @return bool
     */
    private function validate_scopes($scopes)
    {
        $valid_scopes = [
            'openid',
            'profile',
            'email',
            'address',
            'phone',
            'offline_access',
            'read:current_user',
            'update:current_user_metadata'
        ];

        $scope_array = explode(' ', trim($scopes));

        foreach ($scope_array as $scope) {
            if (!in_array($scope, $valid_scopes)) {
                return false;
            }
        }

        return true;
    }

    /**
     * Encrypt client secret
     *
     * @param string $secret Secret to encrypt
     * @return string Encrypted secret
     */
    private function encrypt_secret($secret)
    {
        // Use WordPress salts for encryption
        $key = wp_salt('AUTH_KEY') . wp_salt('SECURE_AUTH_KEY');

        // Simple encryption using WordPress functions
        if (function_exists('openssl_encrypt')) {
            $iv = wp_generate_password(16, false);
            $encrypted = openssl_encrypt($secret, 'AES-256-CBC', $key, 0, $iv);
            return base64_encode($iv . $encrypted);
        }

        // Fallback to WordPress hash
        return wp_hash($secret . $key);
    }

    /**
     * Decrypt client secret
     *
     * @param string $encrypted_secret Encrypted secret
     * @return string Decrypted secret
     */
    private function decrypt_secret($encrypted_secret)
    {
        $key = wp_salt('AUTH_KEY') . wp_salt('SECURE_AUTH_KEY');

        if (function_exists('openssl_decrypt')) {
            $data = base64_decode($encrypted_secret);
            $iv = substr($data, 0, 16);
            $encrypted = substr($data, 16);
            return openssl_decrypt($encrypted, 'AES-256-CBC', $key, 0, $iv);
        }

        // If we can't decrypt, return empty (user will need to re-enter)
        return '';
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
        // Check capabilities first
        if (!current_user_can('manage_options')) {
            wp_send_json_error(['message' => __('Insufficient permissions', 'simple-auth0')]);
        }

        // Verify nonce
        $nonce = isset($_POST['nonce']) ? sanitize_text_field($_POST['nonce']) : '';
        if (!wp_verify_nonce($nonce, 'simple_auth0_admin_nonce')) {
            wp_send_json_error(['message' => __('Security check failed. Please refresh the page and try again.', 'simple-auth0')]);
        }

        // Get current options
        $options = get_option('simple_auth0_options', []);

        // Test connection
        $result = $this->test_auth0_connection($options);

        // Update status in database
        $options['status_last_checked'] = time();
        $options['status_ok'] = $result['success'];
        update_option('simple_auth0_options', $options);

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

        // Validate domain format using our validation method
        if (!$this->validate_auth0_domain($options['domain'])) {
            return ['success' => false, 'message' => __('Invalid Auth0 domain format. Please use format like your-tenant.auth0.com', 'simple-auth0')];
        }

        // Test connection by fetching well-known configuration
        $well_known_url = 'https://' . $options['domain'] . '/.well-known/openid-configuration';

        $response = wp_remote_get($well_known_url, [
            'timeout' => 10,
            'headers' => [
                'User-Agent' => 'Simple Auth0 WordPress Plugin'
            ],
            'sslverify' => true // Ensure SSL verification is enabled
        ]);

        if (is_wp_error($response)) {
            $error_message = $response->get_error_message();
            error_log('Simple Auth0: Connection test failed - ' . $error_message);

            if (strpos($error_message, 'SSL') !== false) {
                return ['success' => false, 'message' => __('SSL connection error. Please check your server\'s SSL configuration.', 'simple-auth0')];
            } elseif (strpos($error_message, 'timeout') !== false) {
                return ['success' => false, 'message' => __('Connection timeout. Please check your internet connection and try again.', 'simple-auth0')];
            } else {
                return ['success' => false, 'message' => sprintf(__('Network error: %s', 'simple-auth0'), $error_message)];
            }
        }

        $response_code = wp_remote_retrieve_response_code($response);

        if ($response_code !== 200) {
            error_log('Simple Auth0: Connection test failed - HTTP ' . $response_code . ' for ' . $options['domain']);

            switch ($response_code) {
                case 404:
                    return ['success' => false, 'message' => __('Auth0 domain not found. Please check your domain spelling.', 'simple-auth0')];
                case 403:
                    return ['success' => false, 'message' => __('Access denied. Please check if your Auth0 tenant is active.', 'simple-auth0')];
                case 500:
                    return ['success' => false, 'message' => __('Auth0 service temporarily unavailable. Please try again later.', 'simple-auth0')];
                default:
                    return ['success' => false, 'message' => sprintf(__('Auth0 service error (HTTP %d). Please try again later.', 'simple-auth0'), $response_code)];
            }
        }

        $body = wp_remote_retrieve_body($response);
        $config = json_decode($body, true);

        if (!$config || !isset($config['issuer'])) {
            return ['success' => false, 'message' => __('Invalid response from Auth0. Please check your domain and try again.', 'simple-auth0')];
        }

        // Verify the issuer matches the domain
        $expected_issuer = 'https://' . $options['domain'] . '/';
        if ($config['issuer'] !== $expected_issuer) {
            return ['success' => false, 'message' => __('Domain mismatch in Auth0 configuration. Please verify your domain.', 'simple-auth0')];
        }

        // Update status
        $this->options['status_last_checked'] = time();
        $this->options['status_ok'] = true;
        update_option('simple_auth0_options', $this->options);

        return ['success' => true, 'message' => __('Successfully connected to Auth0! Your configuration is valid.', 'simple-auth0')];
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

    /**
     * Maybe redirect to Auth0 on login_init
     */
    public function maybe_redirect_to_auth0()
    {
        // Only redirect if Auth0 login is enabled
        if (empty($this->options['enable_auth0_login']) || !$this->options['enable_auth0_login']) {
            return;
        }

        // Check if we have required settings
        if (empty($this->options['domain']) || empty($this->options['client_id'])) {
            return;
        }

        // Don't redirect if we're already in an Auth0 flow
        if (isset($_GET['auth0']) || isset($_GET['code']) || isset($_GET['state'])) {
            return;
        }

        // Don't redirect AJAX requests
        if (wp_doing_ajax()) {
            return;
        }

        // Don't redirect if user is already logged in
        if (is_user_logged_in()) {
            return;
        }

        // Generate Auth0 authorization URL and redirect
        $auth_url = $this->generate_auth0_authorization_url();
        if ($auth_url) {
            wp_redirect($auth_url);
            exit;
        }
    }

    /**
     * Generate Auth0 authorization URL with PKCE
     */
    private function generate_auth0_authorization_url()
    {
        if (empty($this->options['domain']) || empty($this->options['client_id'])) {
            return false;
        }

        // Generate PKCE parameters
        $code_verifier = $this->generate_code_verifier();
        $code_challenge = $this->generate_code_challenge($code_verifier);

        // Store code verifier in transient for later use
        set_transient('auth0_code_verifier_' . wp_get_session_token(), $code_verifier, 600); // 10 minutes

        // Generate state parameter for security
        $state = wp_generate_password(32, false);
        set_transient('auth0_state_' . wp_get_session_token(), $state, 600); // 10 minutes

        // Build authorization URL
        $params = [
            'response_type' => 'code',
            'client_id' => $this->options['client_id'],
            'redirect_uri' => $this->get_redirect_uri(),
            'scope' => $this->options['scopes'] ?? 'openid profile email',
            'state' => $state,
            'code_challenge' => $code_challenge,
            'code_challenge_method' => 'S256'
        ];

        // Add audience if configured
        if (!empty($this->options['audience'])) {
            $params['audience'] = $this->options['audience'];
        }

        $auth_url = 'https://' . $this->options['domain'] . '/authorize?' . http_build_query($params);

        return $auth_url;
    }

    /**
     * Generate PKCE code verifier
     */
    private function generate_code_verifier()
    {
        return rtrim(strtr(base64_encode(random_bytes(32)), '+/', '-_'), '=');
    }

    /**
     * Generate PKCE code challenge
     */
    private function generate_code_challenge($code_verifier)
    {
        return rtrim(strtr(base64_encode(hash('sha256', $code_verifier, true)), '+/', '-_'), '=');
    }

    /**
     * Get redirect URI for Auth0
     */
    private function get_redirect_uri()
    {
        if (!empty($this->options['redirect_uri'])) {
            return $this->options['redirect_uri'];
        }

        // Default to our REST API callback
        return home_url('/wp-json/simple-auth0/v1/callback');
    }

    /**
     * Filter login URL to use Auth0 when enabled
     */
    public function filter_login_url($login_url, $redirect)
    {
        // Only filter if Auth0 login is enabled
        if (empty($this->options['enable_auth0_login']) || !$this->options['enable_auth0_login']) {
            return $login_url;
        }

        // Check if we have required settings
        if (empty($this->options['domain']) || empty($this->options['client_id'])) {
            return $login_url;
        }

        // Don't filter if user is already logged in
        if (is_user_logged_in()) {
            return $login_url;
        }

        // Return the standard login URL - the login_init hook will handle the redirect
        return $login_url;
    }

    /**
     * Handle logout
     */
    public function handle_logout()
    {
        // Only handle Auth0 logout if enabled and configured
        if (empty($this->options['enable_auth0_login']) || !$this->options['enable_auth0_login']) {
            return;
        }

        if (empty($this->options['domain'])) {
            return;
        }

        // Get logout redirect URI
        $logout_redirect = !empty($this->options['logout_redirect_uri']) 
            ? $this->options['logout_redirect_uri'] 
            : home_url();

        // Build Auth0 logout URL
        $logout_params = [
            'returnTo' => $logout_redirect,
            'client_id' => $this->options['client_id']
        ];

        $auth0_logout_url = 'https://' . $this->options['domain'] . '/v2/logout?' . http_build_query($logout_params);

        // Redirect to Auth0 logout
        wp_redirect($auth0_logout_url);
        exit;
    }
}
