<?php

/**
 * Admin functionality
 *
 * @package SimpleAuth0
 */

namespace SimpleAuth0;

// Prevent direct access
if (!defined('ABSPATH')) {
    exit;
}

/**
 * Admin class
 */
class Admin
{

    /**
     * Current tab
     *
     * @var string
     */
    private $current_tab = 'settings';

    /**
     * Available tabs
     *
     * @var array
     */
    private $tabs = [];


    /**
     * Constructor
     */
    public function __construct()
    {
        $this->init_tabs();
        add_action('admin_menu', [$this, 'add_admin_menu']);
        add_action('admin_init', [$this, 'admin_init']);
        add_action('admin_enqueue_scripts', [$this, 'enqueue_admin_scripts']);
        add_action('wp_ajax_simple_auth0_check_connection', [$this, 'ajax_check_connection']);
        add_action('wp_ajax_simple_auth0_export_users', [$this, 'ajax_export_users']);
    }

    /**
     * Initialize tabs
     */
    private function init_tabs()
    {
        $this->tabs = [
            'settings' => [
                'title' => __('Settings', 'simple-auth0'),
                'callback' => [$this, 'render_settings_tab'],
            ],
            'sync' => [
                'title' => __('Sync', 'simple-auth0'),
                'callback' => [$this, 'render_sync_tab'],
            ],
            'help' => [
                'title' => __('Help', 'simple-auth0'),
                'callback' => [$this, 'render_help_tab'],
            ],
        ];

        // Get current tab from URL parameter
        if (isset($_GET['tab']) && array_key_exists($_GET['tab'], $this->tabs)) {
            $this->current_tab = sanitize_text_field($_GET['tab']);
        }
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
        // Register settings
        register_setting('simple_auth0_options', 'simple_auth0_options', [
            'sanitize_callback' => [$this, 'sanitize_options']
        ]);

        // Add settings sections
        add_settings_section(
            'simple_auth0_settings',
            __('Auth0 Configuration', 'simple-auth0'),
            [$this, 'settings_section_callback'],
            'simple-auth0'
        );

        // Add settings fields
        $this->add_settings_fields();
    }

    /**
     * Add settings fields
     */
    private function add_settings_fields()
    {
        $fields = [
            'domain' => [
                'label' => __('Auth0 Domain', 'simple-auth0'),
                'type' => 'text',
                'description' => __('Your Auth0 domain (e.g., your-tenant.us.auth0.com)', 'simple-auth0'),
                'required' => true,
            ],
            'client_id' => [
                'label' => __('Client ID', 'simple-auth0'),
                'type' => 'text',
                'description' => __('Your Auth0 application client ID', 'simple-auth0'),
                'required' => true,
            ],
            'client_secret' => [
                'label' => __('Client Secret', 'simple-auth0'),
                'type' => 'password',
                'description' => __('Your Auth0 application client secret', 'simple-auth0'),
                'required' => true,
            ],
            'audience' => [
                'label' => __('Audience', 'simple-auth0'),
                'type' => 'text',
                'description' => __('API audience (optional, for API access)', 'simple-auth0'),
                'required' => false,
            ],
            'redirect_uri' => [
                'label' => __('Redirect URI', 'simple-auth0'),
                'type' => 'url',
                'description' => __('Callback URL for OAuth flow', 'simple-auth0'),
                'required' => true,
            ],
            'logout_redirect_uri' => [
                'label' => __('Logout Redirect URI', 'simple-auth0'),
                'type' => 'url',
                'description' => __('URL to redirect to after logout (optional)', 'simple-auth0'),
                'required' => false,
            ],
            'scopes' => [
                'label' => __('Scopes', 'simple-auth0'),
                'type' => 'text',
                'description' => __('OAuth scopes (space-separated)', 'simple-auth0'),
                'required' => false,
            ],
            'enable_auth0_login' => [
                'label' => __('Enable Auth0 Login', 'simple-auth0'),
                'type' => 'checkbox',
                'description' => __('Replace WordPress login with Auth0', 'simple-auth0'),
                'required' => false,
            ],
            'auto_sync_users' => [
                'label' => __('Auto-sync Users', 'simple-auth0'),
                'type' => 'checkbox',
                'description' => __('Automatically sync WordPress users to Auth0', 'simple-auth0'),
                'required' => false,
            ],
        ];

        foreach ($fields as $field_id => $field_config) {
            add_settings_field(
                $field_id,
                $field_config['label'],
                [$this, 'field_callback'],
                'simple-auth0',
                'simple_auth0_settings',
                [
                    'field_id' => $field_id,
                    'field_config' => $field_config,
                ]
            );
        }
    }

    /**
     * Settings section callback
     */
    public function settings_section_callback()
    {
        echo '<p>' . esc_html__('Configure your Auth0 application settings below.', 'simple-auth0') . '</p>';
    }

    /**
     * Field callback
     *
     * @param array $args Field arguments.
     */
    public function field_callback($args)
    {
        $field_id = $args['field_id'];
        $field_config = $args['field_config'];
        $options = get_option('simple_auth0_options', []);
        $value = isset($options[$field_id]) ? $options[$field_id] : '';

        // Set default values
        if (empty($value)) {
            switch ($field_id) {
                case 'redirect_uri':
                    $value = home_url('/wp-json/simple-auth0/v1/callback');
                    break;
                case 'scopes':
                    $value = 'openid profile email';
                    break;
                case 'auto_sync_users':
                    $value = true;
                    break;
            }
        }

        $required = $field_config['required'] ? ' required' : '';
        $required_attr = $field_config['required'] ? ' required' : '';

        switch ($field_config['type']) {
            case 'text':
            case 'url':
            case 'password':
                printf(
                    '<input type="%s" id="%s" name="simple_auth0_options[%s]" value="%s" class="regular-text"%s />',
                    esc_attr($field_config['type']),
                    esc_attr($field_id),
                    esc_attr($field_id),
                    esc_attr($value),
                    $required_attr
                );
                break;

            case 'checkbox':
                printf(
                    '<input type="checkbox" id="%s" name="simple_auth0_options[%s]" value="1"%s%s />',
                    esc_attr($field_id),
                    esc_attr($field_id),
                    checked(1, $value, false),
                    $required_attr
                );
                break;
        }

        if (!empty($field_config['description'])) {
            printf(
                '<p class="description">%s</p>',
                esc_html($field_config['description'])
            );
        }
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
            $existing_options = get_option('simple_auth0_options', []);
            $sanitized['client_secret'] = isset($existing_options['client_secret']) ? $existing_options['client_secret'] : '';
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

        return $sanitized;
    }

    /**
     * Enqueue admin scripts
     *
     * @param string $hook Current admin page hook.
     */
    public function enqueue_admin_scripts($hook)
    {
        if ('settings_page_simple-auth0' !== $hook) {
            return;
        }

        wp_enqueue_script('jquery');
        wp_enqueue_style(
            'simple-auth0-admin',
            SIMPLE_AUTH0_PLUGIN_URL . 'admin/css/admin.css',
            [],
            SIMPLE_AUTH0_VERSION
        );
        wp_enqueue_script(
            'simple-auth0-admin',
            SIMPLE_AUTH0_PLUGIN_URL . 'admin/js/admin.js',
            ['jquery'],
            SIMPLE_AUTH0_VERSION,
            true
        );

        // Localize script for AJAX
        wp_localize_script('simple-auth0-admin', 'simpleAuth0', [
            'ajaxUrl' => admin_url('admin-ajax.php'),
            'nonce' => wp_create_nonce('simple_auth0_nonce'),
            'strings' => [
                'checking' => __('Checking connection...', 'simple-auth0'),
                'connected' => __('Connected', 'simple-auth0'),
                'notConnected' => __('Not connected', 'simple-auth0'),
                'error' => __('Error', 'simple-auth0'),
            ],
        ]);
    }

    /**
     * Admin page callback
     */
    public function admin_page()
    {
?>
        <div class="wrap">
            <h1><?php echo esc_html__('Simple Auth0', 'simple-auth0'); ?></h1>

            <?php settings_errors(); ?>

            <div class="simple-auth0-admin">
                <!-- Connection Status -->
                <div class="simple-auth0-status">
                    <h2><?php echo esc_html__('Connection Status', 'simple-auth0'); ?></h2>
                    <div class="status-badge">
                        <span class="status-indicator status-unknown" id="connection-status">
                            <?php echo esc_html__('Checking...', 'simple-auth0'); ?>
                        </span>
                        <button type="button" class="button button-secondary" id="check-connection">
                            <?php echo esc_html__('Re-check', 'simple-auth0'); ?>
                        </button>
                    </div>
                </div>

                <!-- Tabs -->
                <div class="simple-auth0-tabs">
                    <nav class="nav-tab-wrapper">
                        <?php foreach ($this->tabs as $tab_id => $tab_config) : ?>
                            <a href="<?php echo esc_url($this->get_tab_url($tab_id)); ?>"
                                class="nav-tab <?php echo $tab_id === $this->current_tab ? 'nav-tab-active' : ''; ?>">
                                <?php echo esc_html($tab_config['title']); ?>
                            </a>
                        <?php endforeach; ?>
                    </nav>
                </div>

                <!-- Tab Content -->
                <div class="simple-auth0-tab-content">
                    <?php
                    if (isset($this->tabs[$this->current_tab]['callback'])) {
                        call_user_func($this->tabs[$this->current_tab]['callback']);
                    }
                    ?>
                </div>
            </div>
        </div>
    <?php
    }

    /**
     * Get tab URL
     *
     * @param string $tab_id Tab ID.
     * @return string Tab URL.
     */
    private function get_tab_url($tab_id)
    {
        return add_query_arg('tab', $tab_id, admin_url('options-general.php?page=simple-auth0'));
    }

    /**
     * Render Settings tab
     */
    public function render_settings_tab()
    {
    ?>
        <form method="post" action="options.php">
            <?php
            settings_fields('simple_auth0_options');
            do_settings_sections('simple-auth0');
            submit_button();
            ?>
        </form>
    <?php
    }

    /**
     * Render Sync tab
     */
    public function render_sync_tab()
    {
        $user_count = count_users();
        $total_users = $user_count['total_users'];
    ?>
        <div class="sync-tab">
            <h2><?php echo esc_html__('User Synchronization', 'simple-auth0'); ?></h2>

            <div class="sync-info">
                <p><?php
                    printf(
                        esc_html__('You have %d users in your WordPress site.', 'simple-auth0'),
                        $total_users
                    );
                    ?></p>
            </div>

            <div class="sync-actions">
                <button type="button" class="button button-secondary" id="preview-export">
                    <?php echo esc_html__('Preview Export', 'simple-auth0'); ?>
                </button>
                <button type="button" class="button button-primary" id="download-export">
                    <?php echo esc_html__('Download JSON', 'simple-auth0'); ?>
                </button>
            </div>

            <div class="sync-preview" id="sync-preview" style="display: none;">
                <h3><?php echo esc_html__('Export Preview', 'simple-auth0'); ?></h3>
                <pre id="preview-content"></pre>
            </div>

            <div class="sync-instructions">
                <h3><?php echo esc_html__('Import Instructions', 'simple-auth0'); ?></h3>
                <ol>
                    <li><?php echo esc_html__('Go to your Auth0 Dashboard', 'simple-auth0'); ?></li>
                    <li><?php echo esc_html__('Navigate to User Management → Users', 'simple-auth0'); ?></li>
                    <li><?php echo esc_html__('Click "Import Users"', 'simple-auth0'); ?></li>
                    <li><?php echo esc_html__('Upload the downloaded JSON file', 'simple-auth0'); ?></li>
                    <li><?php echo esc_html__('Select the database connection to import into', 'simple-auth0'); ?></li>
                </ol>

                <div class="warning">
                    <strong><?php echo esc_html__('Note:', 'simple-auth0'); ?></strong>
                    <?php echo esc_html__('Password import only works with supported hash algorithms (bcrypt, argon2id). Legacy WordPress hashes may not be importable.', 'simple-auth0'); ?>
                </div>
            </div>
        </div>
    <?php
    }

    /**
     * Render Help tab
     */
    public function render_help_tab()
    {
    ?>
        <div class="help-tab">
            <h2><?php echo esc_html__('Setup Guide', 'simple-auth0'); ?></h2>

            <div class="help-section">
                <h3><?php echo esc_html__('Auth0 Application Configuration', 'simple-auth0'); ?></h3>
                <p><?php echo esc_html__('Configure your Auth0 application with the following settings:', 'simple-auth0'); ?></p>

                <ul>
                    <li><strong><?php echo esc_html__('Allowed Callback URLs:', 'simple-auth0'); ?></strong>
                        <code><?php echo esc_url(home_url('/wp-json/simple-auth0/v1/callback')); ?></code>
                    </li>
                    <li><strong><?php echo esc_html__('Allowed Logout URLs:', 'simple-auth0'); ?></strong>
                        <code><?php echo esc_url(home_url('/wp-login.php')); ?></code>,
                        <code><?php echo esc_url(home_url('/')); ?></code>
                    </li>
                    <li><strong><?php echo esc_html__('Allowed Web Origins:', 'simple-auth0'); ?></strong>
                        <code><?php echo esc_url(home_url()); ?></code>
                    </li>
                    <li><strong><?php echo esc_html__('Application Type:', 'simple-auth0'); ?></strong> <?php echo esc_html__('Regular Web Application', 'simple-auth0'); ?></li>
                    <li><strong><?php echo esc_html__('Token Endpoint Auth Method:', 'simple-auth0'); ?></strong> <?php echo esc_html__('client_secret_post', 'simple-auth0'); ?></li>
                </ul>
            </div>

            <div class="help-section">
                <h3><?php echo esc_html__('Enabling Auth0 Login', 'simple-auth0'); ?></h3>
                <ol>
                    <li><?php echo esc_html__('Configure your Auth0 settings in the Settings tab', 'simple-auth0'); ?></li>
                    <li><?php echo esc_html__('Test the connection using the "Re-check" button', 'simple-auth0'); ?></li>
                    <li><?php echo esc_html__('Enable "Auth0 Login" toggle when connection is successful', 'simple-auth0'); ?></li>
                    <li><?php echo esc_html__('Save settings to activate Auth0 login', 'simple-auth0'); ?></li>
                </ol>
            </div>

            <div class="help-section">
                <h3><?php echo esc_html__('Troubleshooting', 'simple-auth0'); ?></h3>
                <ul>
                    <li><strong><?php echo esc_html__('Connection Issues:', 'simple-auth0'); ?></strong> <?php echo esc_html__('Verify your domain, client ID, and client secret are correct', 'simple-auth0'); ?></li>
                    <li><strong><?php echo esc_html__('Callback Errors:', 'simple-auth0'); ?></strong> <?php echo esc_html__('Ensure the callback URL is added to your Auth0 application settings', 'simple-auth0'); ?></li>
                    <li><strong><?php echo esc_html__('Cookie Issues:', 'simple-auth0'); ?></strong> <?php echo esc_html__('Check that your site uses HTTPS and cookies are enabled', 'simple-auth0'); ?></li>
                    <li><strong><?php echo esc_html__('Clock Skew:', 'simple-auth0'); ?></strong> <?php echo esc_html__('Ensure your server time is synchronized', 'simple-auth0'); ?></li>
                </ul>
            </div>

            <div class="help-section">
                <h3><?php echo esc_html__('Support', 'simple-auth0'); ?></h3>
                <p>
                    <?php echo esc_html__('For additional help, please visit:', 'simple-auth0'); ?>
                    <a href="https://github.com/your-username/simple-auth0" target="_blank">
                        <?php echo esc_html__('GitHub Repository', 'simple-auth0'); ?>
                    </a>
                </p>
            </div>
        </div>
<?php
    }

    /**
     * AJAX handler for connection check
     */
    public function ajax_check_connection()
    {
        check_ajax_referer('simple_auth0_nonce', 'nonce');

        if (!current_user_can('manage_options')) {
            wp_die(__('Insufficient permissions', 'simple-auth0'));
        }

        $plugin = Simple_Auth0::get_instance();
        $options = $plugin->get_options();

        if (empty($options['domain']) || empty($options['client_id'])) {
            wp_send_json_error([
                'message' => __('Auth0 configuration incomplete', 'simple-auth0')
            ]);
        }

        // Simple connection test - try to fetch OIDC discovery document
        $discovery_url = 'https://' . $options['domain'] . '/.well-known/openid_configuration';

        $response = wp_remote_get($discovery_url, [
            'timeout' => 10,
            'sslverify' => true,
        ]);

        if (is_wp_error($response)) {
            wp_send_json_error([
                'message' => $response->get_error_message()
            ]);
        }

        $body = wp_remote_retrieve_body($response);
        $data = json_decode($body, true);

        if (empty($data) || !isset($data['issuer'])) {
            wp_send_json_error([
                'message' => __('Invalid Auth0 domain or configuration', 'simple-auth0')
            ]);
        }

        wp_send_json_success([
            'message' => __('Connected successfully', 'simple-auth0')
        ]);
    }

    /**
     * AJAX handler for user export
     */
    public function ajax_export_users()
    {
        check_ajax_referer('simple_auth0_nonce', 'nonce');

        if (!current_user_can('manage_options')) {
            wp_die(__('Insufficient permissions', 'simple-auth0'));
        }

        $action = sanitize_text_field($_POST['action_type'] ?? '');

        if ($action === 'preview') {
            $this->export_users_preview();
        } elseif ($action === 'download') {
            $this->export_users_download();
        } else {
            wp_send_json_error(['message' => __('Invalid action', 'simple-auth0')]);
        }
    }

    /**
     * Export users preview
     */
    private function export_users_preview()
    {
        $users = get_users(['number' => 20]); // Preview first 20 users
        $export_data = $this->prepare_export_data($users);

        wp_send_json_success([
            'preview' => json_encode($export_data, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES)
        ]);
    }

    /**
     * Export users download
     */
    private function export_users_download()
    {
        $users = get_users();
        $export_data = $this->prepare_export_data($users);

        $filename = 'auth0-users-export-' . date('Y-m-d-H-i-s') . '.json';

        header('Content-Type: application/json');
        header('Content-Disposition: attachment; filename="' . $filename . '"');
        header('Content-Length: ' . strlen(json_encode($export_data)));

        echo json_encode($export_data, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
        exit;
    }

    /**
     * Prepare export data in Auth0 format
     *
     * @param array $users WordPress users.
     * @return array Export data.
     */
    private function prepare_export_data($users)
    {
        $export_data = [];

        foreach ($users as $user) {
            $user_data = [
                'email' => $user->user_email,
                'email_verified' => true, // Best effort
                'user_id' => 'wp|' . $user->ID,
                'name' => $user->display_name,
                'given_name' => $user->first_name,
                'family_name' => $user->last_name,
            ];

            // Add password hash if supported
            $password_hash = $this->get_user_password_hash($user);
            if ($password_hash) {
                $user_data['custom_password_hash'] = $password_hash;
            } else {
                $user_data['password_import_unavailable'] = true;
            }

            $export_data[] = $user_data;
        }

        return $export_data;
    }

    /**
     * Get user password hash in Auth0 format
     *
     * @param \WP_User $user WordPress user.
     * @return array|null Password hash data or null if unsupported.
     */
    private function get_user_password_hash($user)
    {
        global $wp_hasher;

        if (!$wp_hasher) {
            require_once ABSPATH . WPINC . '/class-phpass.php';
            $wp_hasher = new \PasswordHash(8, true);
        }

        // Get the stored hash
        $stored_hash = $user->user_pass;

        // Try to detect hash algorithm
        if (strpos($stored_hash, '$2y$') === 0) {
            // bcrypt
            return [
                'algorithm' => 'bcrypt',
                'hash' => [
                    'value' => $stored_hash,
                ],
            ];
        } elseif (strpos($stored_hash, '$argon2id$') === 0) {
            // argon2id
            return [
                'algorithm' => 'argon2id',
                'hash' => [
                    'value' => $stored_hash,
                ],
            ];
        }

        // Unsupported hash format
        return null;
    }
}
