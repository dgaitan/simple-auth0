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
                    <tr>
                        <th scope="row">
                            <label for="simple_auth0_enable_login"><?php _e('Enable Auth0 Login', 'simple-auth0'); ?></label>
                        </th>
                        <td>
                            <label>
                                <input type="checkbox" id="simple_auth0_enable_login" name="simple_auth0_options[enable_auth0_login]"
                                    value="1" <?php checked(!empty($this->options['enable_auth0_login'])); ?> />
                                <?php _e('Replace WordPress login with Auth0', 'simple-auth0'); ?>
                            </label>
                            <p class="description"><?php _e('⚠️ Only enable this after configuring Auth0 settings above', 'simple-auth0'); ?></p>
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
