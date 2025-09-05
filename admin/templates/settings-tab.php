<?php

/**
 * Settings tab template
 * 
 * @var array $options
 */

if (!defined('ABSPATH')) {
    exit;
}
?>

<div class="simple-auth0-card">
    <h2><?php _e('Auth0 Configuration', 'simple-auth0'); ?></h2>
    <p><?php _e('Configure your Auth0 settings below. Auth0 login is currently disabled by default.', 'simple-auth0'); ?></p>

    <form method="post" action="options.php">
        <?php
        settings_fields('simple_auth0_options');
        do_settings_sections('simple_auth0');
        ?>

        <table class="form-table" role="presentation">
            <tr>
                <th scope="row">
                    <label for="simple_auth0_domain"><?php _e('Auth0 Domain', 'simple-auth0'); ?></label>
                </th>
                <td>
                    <input type="text"
                        id="simple_auth0_domain"
                        name="simple_auth0_options[domain]"
                        value="<?php echo esc_attr($options['domain'] ?? ''); ?>"
                        class="regular-text"
                        placeholder="your-tenant.auth0.com" />
                    <p class="description">
                        <?php _e('Your Auth0 domain (e.g., your-tenant.auth0.com)', 'simple-auth0'); ?>
                    </p>
                </td>
            </tr>

            <tr>
                <th scope="row">
                    <label for="simple_auth0_client_id"><?php _e('Client ID', 'simple-auth0'); ?></label>
                </th>
                <td>
                    <input type="text"
                        id="simple_auth0_client_id"
                        name="simple_auth0_options[client_id]"
                        value="<?php echo esc_attr($options['client_id'] ?? ''); ?>"
                        class="regular-text" />
                    <p class="description">
                        <?php _e('Your Auth0 application Client ID', 'simple-auth0'); ?>
                    </p>
                </td>
            </tr>

            <tr>
                <th scope="row">
                    <label for="simple_auth0_client_secret"><?php _e('Client Secret', 'simple-auth0'); ?></label>
                </th>
                <td>
                    <input type="password"
                        id="simple_auth0_client_secret"
                        name="simple_auth0_options[client_secret]"
                        value=""
                        class="regular-text"
                        placeholder="<?php echo !empty($options['client_secret']) ? '••••••••••••••••' : ''; ?>" />
                    <p class="description">
                        <?php _e('Your Auth0 application Client Secret. Leave blank to keep current value.', 'simple-auth0'); ?>
                    </p>
                </td>
            </tr>

            <tr>
                <th scope="row">
                    <label for="simple_auth0_redirect_uri"><?php _e('Redirect URI', 'simple-auth0'); ?></label>
                </th>
                <td>
                    <input type="text"
                        id="simple_auth0_redirect_uri"
                        name="simple_auth0_options[redirect_uri]"
                        value="<?php echo esc_attr($options['redirect_uri'] ?? home_url('/wp-json/simple-auth0/v1/callback')); ?>"
                        class="regular-text"
                        readonly />
                    <p class="description">
                        <?php _e('This URL must be added to your Auth0 application\'s Allowed Callback URLs', 'simple-auth0'); ?>
                    </p>
                </td>
            </tr>

            <tr>
                <th scope="row">
                    <label for="simple_auth0_scopes"><?php _e('Scopes', 'simple-auth0'); ?></label>
                </th>
                <td>
                    <input type="text"
                        id="simple_auth0_scopes"
                        name="simple_auth0_options[scopes]"
                        value="<?php echo esc_attr($options['scopes'] ?? 'openid profile email'); ?>"
                        class="regular-text" />
                    <p class="description">
                        <?php _e('Space-separated list of scopes to request from Auth0', 'simple-auth0'); ?>
                    </p>
                </td>
            </tr>

            <tr>
                <th scope="row">
                    <label for="simple_auth0_audience"><?php _e('Audience (Optional)', 'simple-auth0'); ?></label>
                </th>
                <td>
                    <input type="text"
                        id="simple_auth0_audience"
                        name="simple_auth0_options[audience]"
                        value="<?php echo esc_attr($options['audience'] ?? ''); ?>"
                        class="regular-text" />
                    <p class="description">
                        <?php _e('API identifier for accessing protected resources (optional)', 'simple-auth0'); ?>
                    </p>
                </td>
            </tr>

            <tr>
                <th scope="row">
                    <label for="simple_auth0_enable_login"><?php _e('Enable Auth0 Login', 'simple-auth0'); ?></label>
                </th>
                <td>
                    <fieldset>
                        <label for="simple_auth0_enable_login">
                            <input type="checkbox"
                                id="simple_auth0_enable_login"
                                name="simple_auth0_options[enable_auth0_login]"
                                value="1"
                                <?php checked($options['enable_auth0_login'] ?? false); ?>
                                <?php echo (empty($options['domain']) || empty($options['client_id'])) ? 'disabled' : ''; ?> />
                            <?php _e('Replace WordPress login with Auth0', 'simple-auth0'); ?>
                        </label>
                        <?php if (empty($options['domain']) || empty($options['client_id'])) : ?>
                            <p class="description auth0-toggle-disabled">
                                <?php _e('Please configure Auth0 Domain and Client ID first, then test the connection.', 'simple-auth0'); ?>
                            </p>
                        <?php else : ?>
                            <p class="description">
                                <?php _e('When enabled, users will be redirected to Auth0 for login instead of the WordPress login form.', 'simple-auth0'); ?>
                            </p>
                        <?php endif; ?>
                    </fieldset>
                </td>
            </tr>
        </table>

        <?php submit_button(__('Save Settings', 'simple-auth0'), 'primary', 'submit', false, ['class' => 'submit-btn']); ?>
    </form>
</div>