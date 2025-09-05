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
     * Initialize WordPress hooks
     */
    private function init_hooks()
    {
        // Only initialize admin hooks if we're in admin
        if (is_admin()) {
            add_action('admin_menu', [$this, 'add_admin_menu']);
            add_action('admin_init', [$this, 'admin_init']);
            add_action('admin_enqueue_scripts', [$this, 'enqueue_admin_scripts']);
        }
    }

    /**
     * Admin init
     */
    public function admin_init()
    {
        // Register settings
        register_setting('simple_auth0_options', 'simple_auth0_options', [
            'sanitize_callback' => [$this, 'sanitize_options']
        ]);

        // Add AJAX handlers for connection testing
        add_action('wp_ajax_simple_auth0_test_connection', [$this, 'ajax_test_connection']);
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

        // Handle client_secret (only update if not empty)
        if (isset($input['client_secret']) && !empty($input['client_secret'])) {
            $sanitized['client_secret'] = sanitize_text_field($input['client_secret']);
        } else {
            // Keep existing secret if not provided
            $sanitized['client_secret'] = $this->options['client_secret'] ?? '';
        }

        // Sanitize enable_auth0_login
        $sanitized['enable_auth0_login'] = !empty($input['enable_auth0_login']);

        // Preserve other options
        $sanitized['audience'] = $this->options['audience'] ?? '';
        $sanitized['redirect_uri'] = $this->options['redirect_uri'] ?? home_url('/wp-json/simple-auth0/v1/callback');
        $sanitized['logout_redirect_uri'] = $this->options['logout_redirect_uri'] ?? home_url();
        $sanitized['scopes'] = $this->options['scopes'] ?? 'openid profile email';
        $sanitized['auto_sync_users'] = $this->options['auto_sync_users'] ?? true;
        $sanitized['export_hash_algorithm'] = $this->options['export_hash_algorithm'] ?? '';
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

        // Add inline CSS for status badge
        $css = '
        .simple-auth0-status {
            margin: 20px 0;
            padding: 15px;
            background: #f1f1f1;
            border: 1px solid #ccd0d4;
            border-radius: 4px;
        }
        .status-badge {
            display: inline-flex;
            align-items: center;
            padding: 8px 12px;
            border-radius: 4px;
            font-weight: 500;
        }
        .status-badge.connected {
            background: #d4edda;
            color: #155724;
            border: 1px solid #c3e6cb;
        }
        .status-badge.not-connected {
            background: #f8d7da;
            color: #721c24;
            border: 1px solid #f5c6cb;
        }
        .status-badge.checking {
            background: #fff3cd;
            color: #856404;
            border: 1px solid #ffeaa7;
        }
        .status-indicator {
            width: 8px;
            height: 8px;
            border-radius: 50%;
            margin-right: 8px;
            display: inline-block;
        }
        .status-badge.connected .status-indicator {
            background: #28a745;
        }
        .status-badge.not-connected .status-indicator {
            background: #dc3545;
        }
        .status-badge.checking .status-indicator {
            background: #ffc107;
            animation: pulse 1.5s infinite;
        }
        @keyframes pulse {
            0% { opacity: 1; }
            50% { opacity: 0.5; }
            100% { opacity: 1; }
        }
        .auth0-toggle-disabled {
            opacity: 0.6;
            pointer-events: none;
        }
        ';

        wp_add_inline_style('wp-admin', $css);

        // Add inline JavaScript for connection testing
        $js = '
        jQuery(document).ready(function($) {
            // Test connection on page load
            testConnection();
            
            // Test connection button click
            $("#test-connection").on("click", function() {
                testConnection();
            });
            
            function testConnection() {
                var $status = $("#connection-status");
                var $button = $("#test-connection");
                var $toggle = $("#simple_auth0_enable_login");
                
                $status.removeClass("connected not-connected").addClass("checking");
                $status.find(".status-text").text("' . esc_js(__('Testing connection...', 'simple-auth0')) . '");
                $button.prop("disabled", true);
                
                $.post(ajaxurl, {
                    action: "simple_auth0_test_connection",
                    nonce: "' . wp_create_nonce('simple_auth0_test_connection') . '"
                }, function(response) {
                    if (response.success) {
                        $status.removeClass("checking").addClass("connected");
                        $status.find(".status-text").text(response.data.message);
                        $toggle.prop("disabled", false).closest("tr").removeClass("auth0-toggle-disabled");
                    } else {
                        $status.removeClass("checking").addClass("not-connected");
                        $status.find(".status-text").text(response.data.message || "' . esc_js(__('Connection failed', 'simple-auth0')) . '");
                        $toggle.prop("disabled", true).closest("tr").addClass("auth0-toggle-disabled");
                    }
                    $button.prop("disabled", false);
                }).fail(function() {
                    $status.removeClass("checking").addClass("not-connected");
                    $status.find(".status-text").text("' . esc_js(__('Connection test failed', 'simple-auth0')) . '");
                    $button.prop("disabled", false);
                });
            }
        });
        ';

        wp_add_inline_script('jquery', $js);
    }

    /**
     * AJAX handler for testing Auth0 connection
     */
    public function ajax_test_connection()
    {
        // Verify nonce
        if (!wp_verify_nonce($_POST['nonce'] ?? '', 'simple_auth0_test_connection')) {
            wp_send_json_error(['message' => __('Security check failed', 'simple-auth0')]);
        }

        // Check user capabilities
        if (!current_user_can('manage_options')) {
            wp_send_json_error(['message' => __('Insufficient permissions', 'simple-auth0')]);
        }

        // Get current options
        $options = $this->get_options();

        // Check if required fields are filled
        if (empty($options['domain']) || empty($options['client_id'])) {
            wp_send_json_error(['message' => __('Auth0 Domain and Client ID are required', 'simple-auth0')]);
        }

        // Test connection by fetching Auth0's well-known configuration
        $test_result = $this->test_auth0_connection($options);

        if ($test_result['success']) {
            wp_send_json_success(['message' => $test_result['message']]);
        } else {
            wp_send_json_error(['message' => $test_result['message']]);
        }
    }

    /**
     * Test Auth0 connection
     *
     * @param array $options Plugin options.
     * @return array Test result.
     */
    private function test_auth0_connection($options)
    {
        $domain = $options['domain'];

        // Ensure domain has proper format
        if (!preg_match('/^[a-zA-Z0-9][a-zA-Z0-9-]*[a-zA-Z0-9]*\.auth0\.com$/', $domain)) {
            return [
                'success' => false,
                'message' => __('Invalid Auth0 domain format', 'simple-auth0')
            ];
        }

        // Test by fetching the well-known configuration
        $well_known_url = "https://{$domain}/.well-known/openid_configuration";

        $response = wp_remote_get($well_known_url, [
            'timeout' => 10,
            'headers' => [
                'User-Agent' => 'Simple Auth0 WordPress Plugin'
            ]
        ]);

        if (is_wp_error($response)) {
            return [
                'success' => false,
                'message' => sprintf(__('Cannot reach Auth0: %s', 'simple-auth0'), $response->get_error_message())
            ];
        }

        $response_code = wp_remote_retrieve_response_code($response);
        if ($response_code !== 200) {
            return [
                'success' => false,
                'message' => sprintf(__('Auth0 returned error code: %d', 'simple-auth0'), $response_code)
            ];
        }

        $body = wp_remote_retrieve_body($response);
        $config = json_decode($body, true);

        if (!$config || !isset($config['issuer'])) {
            return [
                'success' => false,
                'message' => __('Invalid Auth0 configuration response', 'simple-auth0')
            ];
        }

        // Update status in options
        $this->options['status_last_checked'] = time();
        $this->options['status_ok'] = true;
        update_option('simple_auth0_options', $this->options);

        return [
            'success' => true,
            'message' => __('Connected to Auth0 successfully', 'simple-auth0')
        ];
    }

    /**
     * Load plugin options
     */
    private function load_options()
    {
        $this->options = get_option('simple_auth0_options', []);
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
     * Update plugin options
     *
     * @param array $options New options.
     */
    public function update_options($options)
    {
        $this->options = $options;
        update_option('simple_auth0_options', $options);
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
     * Admin page
     */
    public function admin_page()
    {
        // Get current tab
        $current_tab = isset($_GET['tab']) ? sanitize_text_field($_GET['tab']) : 'settings';

        // Define tabs
        $tabs = [
            'settings' => __('Settings', 'simple-auth0'),
            'sync' => __('Sync', 'simple-auth0'),
            'help' => __('Help', 'simple-auth0'),
        ];

?>
        <div class="wrap">
            <h1><?php echo esc_html(get_admin_page_title()); ?></h1>

            <div class="simple-auth0-status">
                <span class="status-badge" id="connection-status">
                    <span class="status-indicator"></span>
                    <span class="status-text"><?php _e('Checking connection...', 'simple-auth0'); ?></span>
                </span>
                <button type="button" class="button button-secondary" id="test-connection" style="margin-left: 10px;">
                    <?php _e('Test Connection', 'simple-auth0'); ?>
                </button>
            </div>

            <nav class="nav-tab-wrapper wp-clearfix">
                <?php foreach ($tabs as $tab_key => $tab_label) : ?>
                    <a href="<?php echo esc_url(admin_url('options-general.php?page=simple-auth0&tab=' . $tab_key)); ?>"
                        class="nav-tab <?php echo $current_tab === $tab_key ? 'nav-tab-active' : ''; ?>">
                        <?php echo esc_html($tab_label); ?>
                    </a>
                <?php endforeach; ?>
            </nav>

            <div class="tab-content">
                <?php
                switch ($current_tab) {
                    case 'settings':
                        $this->render_settings_tab();
                        break;
                    case 'sync':
                        $this->render_sync_tab();
                        break;
                    case 'help':
                        $this->render_help_tab();
                        break;
                    default:
                        $this->render_settings_tab();
                        break;
                }
                ?>
            </div>
        </div>
    <?php
    }

    /**
     * Render settings tab
     */
    private function render_settings_tab()
    {
    ?>
        <div class="simple-auth0-settings">
            <h2><?php _e('Auth0 Configuration', 'simple-auth0'); ?></h2>
            <p><?php _e('Configure your Auth0 settings below. Auth0 login is currently disabled by default.', 'simple-auth0'); ?></p>

            <form method="post" action="options.php">
                <?php
                settings_fields('simple_auth0_options');
                do_settings_sections('simple_auth0');
                ?>

                <table class="form-table">
                    <tr>
                        <th scope="row">
                            <label for="simple_auth0_domain"><?php _e('Auth0 Domain', 'simple-auth0'); ?></label>
                        </th>
                        <td>
                            <input type="text" id="simple_auth0_domain" name="simple_auth0_options[domain]"
                                value="<?php echo esc_attr($this->options['domain'] ?? ''); ?>"
                                class="regular-text" placeholder="your-tenant.us.auth0.com" />
                            <p class="description"><?php _e('Your Auth0 tenant domain (e.g., your-tenant.us.auth0.com)', 'simple-auth0'); ?></p>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row">
                            <label for="simple_auth0_client_id"><?php _e('Client ID', 'simple-auth0'); ?></label>
                        </th>
                        <td>
                            <input type="text" id="simple_auth0_client_id" name="simple_auth0_options[client_id]"
                                value="<?php echo esc_attr($this->options['client_id'] ?? ''); ?>"
                                class="regular-text" />
                            <p class="description"><?php _e('Your Auth0 application Client ID', 'simple-auth0'); ?></p>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row">
                            <label for="simple_auth0_client_secret"><?php _e('Client Secret', 'simple-auth0'); ?></label>
                        </th>
                        <td>
                            <input type="password" id="simple_auth0_client_secret" name="simple_auth0_options[client_secret]"
                                value="" class="regular-text" />
                            <p class="description"><?php _e('Your Auth0 application Client Secret (leave blank to keep current)', 'simple-auth0'); ?></p>
                        </td>
                    </tr>
                    <tr class="auth0-toggle-row">
                        <th scope="row">
                            <label for="simple_auth0_enable_login"><?php _e('Enable Auth0 Login', 'simple-auth0'); ?></label>
                        </th>
                        <td>
                            <label>
                                <input type="checkbox" id="simple_auth0_enable_login" name="simple_auth0_options[enable_auth0_login]"
                                    value="1" <?php checked(!empty($this->options['enable_auth0_login'])); ?>
                                    <?php echo (empty($this->options['domain']) || empty($this->options['client_id'])) ? 'disabled' : ''; ?> />
                                <?php _e('Replace WordPress login with Auth0', 'simple-auth0'); ?>
                            </label>
                            <p class="description">
                                <?php if (empty($this->options['domain']) || empty($this->options['client_id'])) : ?>
                                    <span style="color: #d63638;">⚠️ <?php _e('Configure Auth0 Domain and Client ID above to enable this option', 'simple-auth0'); ?></span>
                                <?php else : ?>
                                    <span style="color: #00a32a;">✅ <?php _e('Auth0 credentials configured. You can enable Auth0 login.', 'simple-auth0'); ?></span>
                                <?php endif; ?>
                            </p>
                        </td>
                    </tr>
                </table>

                <?php submit_button(); ?>
            </form>
        </div>
    <?php
    }

    /**
     * Render sync tab
     */
    private function render_sync_tab()
    {
    ?>
        <div class="simple-auth0-sync">
            <h2><?php _e('User Sync', 'simple-auth0'); ?></h2>
            <p><?php _e('Export your WordPress users to Auth0-compatible format.', 'simple-auth0'); ?></p>

            <div class="sync-actions">
                <button type="button" class="button button-secondary" id="preview-export">
                    <?php _e('Preview Export', 'simple-auth0'); ?>
                </button>
                <button type="button" class="button button-primary" id="download-export">
                    <?php _e('Download Export', 'simple-auth0'); ?>
                </button>
            </div>

            <div id="export-preview" style="display: none;">
                <h3><?php _e('Export Preview', 'simple-auth0'); ?></h3>
                <pre id="preview-content"></pre>
            </div>
        </div>
    <?php
    }

    /**
     * Render help tab
     */
    private function render_help_tab()
    {
    ?>
        <div class="simple-auth0-help">
            <h2><?php _e('Auth0 Setup Guide', 'simple-auth0'); ?></h2>

            <h3><?php _e('1. Auth0 Application Configuration', 'simple-auth0'); ?></h3>
            <p><?php _e('In your Auth0 Dashboard, configure your application with these settings:', 'simple-auth0'); ?></p>
            <ul>
                <li><strong><?php _e('Allowed Callback URLs:', 'simple-auth0'); ?></strong> <code><?php echo esc_html(home_url('/wp-json/simple-auth0/v1/callback')); ?></code></li>
                <li><strong><?php _e('Allowed Logout URLs:', 'simple-auth0'); ?></strong> <code><?php echo esc_html(home_url('/wp-login.php')); ?></code>, <code><?php echo esc_html(home_url('/')); ?></code></li>
                <li><strong><?php _e('Allowed Web Origins:', 'simple-auth0'); ?></strong> <code><?php echo esc_html(home_url()); ?></code></li>
                <li><strong><?php _e('Application Type:', 'simple-auth0'); ?></strong> <?php _e('Regular Web Application', 'simple-auth0'); ?></li>
            </ul>

            <h3><?php _e('2. Plugin Configuration', 'simple-auth0'); ?></h3>
            <ol>
                <li><?php _e('Go to the Settings tab above', 'simple-auth0'); ?></li>
                <li><?php _e('Enter your Auth0 Domain and Client ID', 'simple-auth0'); ?></li>
                <li><?php _e('Enter your Client Secret', 'simple-auth0'); ?></li>
                <li><?php _e('Test the connection', 'simple-auth0'); ?></li>
                <li><?php _e('Enable Auth0 Login when ready', 'simple-auth0'); ?></li>
            </ol>

            <h3><?php _e('3. User Migration', 'simple-auth0'); ?></h3>
            <p><?php _e('Use the Sync tab to export your WordPress users for import into Auth0.', 'simple-auth0'); ?></p>
        </div>
<?php
    }
}
