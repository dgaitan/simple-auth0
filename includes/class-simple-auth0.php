<?php

/**
 * Main plugin class
 *
 * @package SimpleAuth0
 */

namespace SimpleAuth0;

// Prevent direct access
if (!defined('ABSPATH')) {
    exit;
}

/**
 * Main Simple Auth0 plugin class
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
        $this->load_dependencies();
    }

    /**
     * Load plugin options
     */
    private function load_options()
    {
        $this->options = get_option('simple_auth0_options', []);
    }

    /**
     * Initialize WordPress hooks
     */
    private function init_hooks()
    {
        add_action('init', [$this, 'init']);
        add_action('admin_menu', [$this, 'add_admin_menu']);
        add_action('admin_init', [$this, 'admin_init']);

        // REST API routes
        add_action('rest_api_init', [$this, 'register_rest_routes']);

        // Authentication hooks (only if Auth0 login is enabled)
        if ($this->is_auth0_login_enabled()) {
            $this->init_auth_hooks();
        }
    }

    /**
     * Initialize plugin
     */
    public function init()
    {
        // Load text domain for internationalization
        load_plugin_textdomain('simple-auth0', false, dirname(SIMPLE_AUTH0_PLUGIN_BASENAME) . '/languages');
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
     * Initialize admin settings
     */
    public function admin_init()
    {
        register_setting('simple_auth0_options', 'simple_auth0_options', [
            'sanitize_callback' => [$this, 'sanitize_options']
        ]);
    }

    /**
     * Register REST API routes
     */
    public function register_rest_routes()
    {
        // OAuth callback route
        register_rest_route('simple-auth0/v1', '/callback', [
            'methods' => ['GET', 'POST'],
            'callback' => [$this, 'handle_oauth_callback'],
            'permission_callback' => '__return_true', // Public endpoint
        ]);

        // Logout route (optional)
        register_rest_route('simple-auth0/v1', '/logout', [
            'methods' => ['GET', 'POST'],
            'callback' => [$this, 'handle_logout'],
            'permission_callback' => '__return_true', // Public endpoint
        ]);
    }

    /**
     * Initialize authentication hooks
     */
    private function init_auth_hooks()
    {
        // Redirect login to Auth0
        add_action('login_init', [$this, 'redirect_to_auth0']);

        // Handle authentication
        add_filter('authenticate', [$this, 'authenticate_user'], 20, 3);

        // Modify login URL
        add_filter('login_url', [$this, 'modify_login_url'], 10, 2);
    }

    /**
     * Load plugin dependencies
     */
    private function load_dependencies()
    {
        // Load admin classes
        if (is_admin()) {
            require_once SIMPLE_AUTH0_PLUGIN_DIR . 'admin/class-admin.php';
            new Admin();
        }

        // Load REST API classes
        require_once SIMPLE_AUTH0_PLUGIN_DIR . 'rest-api/class-oauth-handler.php';
        new OAuth_Handler();
    }

    /**
     * Check if Auth0 login is enabled
     *
     * @return bool
     */
    public function is_auth0_login_enabled()
    {
        return !empty($this->options['enable_auth0_login']);
    }

    /**
     * Get plugin options
     *
     * @return array
     */
    public function get_options()
    {
        return $this->options;
    }

    /**
     * Get a specific option value
     *
     * @param string $key Option key.
     * @param mixed  $default Default value if option doesn't exist.
     * @return mixed
     */
    public function get_option($key, $default = null)
    {
        return isset($this->options[$key]) ? $this->options[$key] : $default;
    }

    /**
     * Update plugin options
     *
     * @param array $options New options.
     * @return bool
     */
    public function update_options($options)
    {
        $this->options = array_merge($this->options, $options);
        return update_option('simple_auth0_options', $this->options);
    }

    /**
     * Sanitize options
     *
     * @param array $input Raw input options.
     * @return array Sanitized options.
     */
    public function sanitize_options($input)
    {
        $sanitized = [];

        // Sanitize domain
        if (isset($input['domain'])) {
            $sanitized['domain'] = sanitize_text_field($input['domain']);
        }

        // Sanitize client_id
        if (isset($input['client_id'])) {
            $sanitized['client_id'] = sanitize_text_field($input['client_id']);
        }

        // Sanitize client_secret (only update if not empty)
        if (isset($input['client_secret']) && !empty($input['client_secret'])) {
            $sanitized['client_secret'] = sanitize_text_field($input['client_secret']);
        } else {
            // Keep existing secret if not provided
            $sanitized['client_secret'] = $this->get_option('client_secret', '');
        }

        // Sanitize audience
        if (isset($input['audience'])) {
            $sanitized['audience'] = sanitize_text_field($input['audience']);
        }

        // Sanitize redirect_uri
        if (isset($input['redirect_uri'])) {
            $sanitized['redirect_uri'] = esc_url_raw($input['redirect_uri']);
        }

        // Sanitize logout_redirect_uri
        if (isset($input['logout_redirect_uri'])) {
            $sanitized['logout_redirect_uri'] = esc_url_raw($input['logout_redirect_uri']);
        }

        // Sanitize scopes
        if (isset($input['scopes'])) {
            $sanitized['scopes'] = sanitize_text_field($input['scopes']);
        }

        // Sanitize boolean options
        $sanitized['enable_auth0_login'] = isset($input['enable_auth0_login']) ? (bool) $input['enable_auth0_login'] : false;
        $sanitized['auto_sync_users'] = isset($input['auto_sync_users']) ? (bool) $input['auto_sync_users'] : true;

        // Sanitize export_hash_algorithm
        if (isset($input['export_hash_algorithm'])) {
            $sanitized['export_hash_algorithm'] = sanitize_text_field($input['export_hash_algorithm']);
        }

        return $sanitized;
    }

    /**
     * Admin page callback
     */
    public function admin_page()
    {
        // This will be implemented in the Admin class
        echo '<div class="wrap">';
        echo '<h1>' . esc_html__('Simple Auth0 Settings', 'simple-auth0') . '</h1>';
        echo '<p>' . esc_html__('Admin interface coming soon...', 'simple-auth0') . '</p>';
        echo '</div>';
    }

    /**
     * Redirect to Auth0 for login
     */
    public function redirect_to_auth0()
    {
        // This will be implemented in the OAuth handler
    }

    /**
     * Authenticate user
     *
     * @param mixed  $user User object.
     * @param string $username Username.
     * @param string $password Password.
     * @return mixed
     */
    public function authenticate_user($user, $username, $password)
    {
        // This will be implemented in the OAuth handler
        return $user;
    }

    /**
     * Modify login URL
     *
     * @param string $login_url Login URL.
     * @param string $redirect Redirect URL.
     * @return string
     */
    public function modify_login_url($login_url, $redirect)
    {
        // This will be implemented in the OAuth handler
        return $login_url;
    }

    /**
     * Handle OAuth callback
     *
     * @param \WP_REST_Request $request REST request object.
     * @return \WP_REST_Response
     */
    public function handle_oauth_callback($request)
    {
        // This will be implemented in the OAuth handler
        return new \WP_REST_Response(['message' => 'OAuth callback handler'], 200);
    }

    /**
     * Handle logout
     *
     * @param \WP_REST_Request $request REST request object.
     * @return \WP_REST_Response
     */
    public function handle_logout($request)
    {
        // This will be implemented in the OAuth handler
        return new \WP_REST_Response(['message' => 'Logout handler'], 200);
    }
}
