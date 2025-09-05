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
     * Constructor
     */
    public function __construct()
    {
        add_action('admin_menu', [$this, 'add_admin_menu']);
        add_action('admin_init', [$this, 'admin_init']);
        add_action('admin_enqueue_scripts', [$this, 'enqueue_admin_scripts']);
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
    }

    /**
     * Admin page callback
     */
    public function admin_page()
    {
?>
        <div class="wrap">
            <h1><?php echo esc_html__('Simple Auth0 Settings', 'simple-auth0'); ?></h1>

            <?php settings_errors(); ?>

            <div class="simple-auth0-admin">
                <div class="simple-auth0-status">
                    <h2><?php echo esc_html__('Connection Status', 'simple-auth0'); ?></h2>
                    <div class="status-badge">
                        <span class="status-indicator status-unknown"><?php echo esc_html__('Checking...', 'simple-auth0'); ?></span>
                    </div>
                </div>

                <form method="post" action="options.php">
                    <?php
                    settings_fields('simple_auth0_options');
                    do_settings_sections('simple-auth0');
                    submit_button();
                    ?>
                </form>
            </div>
        </div>
<?php
    }
}
