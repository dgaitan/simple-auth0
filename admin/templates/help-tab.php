<?php

/**
 * Help tab template
 */

if (!defined('ABSPATH')) {
    exit;
}
?>

<div class="simple-auth0-card help">
    <h2><?php _e('Auth0 Setup Guide', 'simple-auth0'); ?></h2>

    <div class="help-section">
        <h3><?php _e('1. Auth0 Application Configuration', 'simple-auth0'); ?></h3>
        <p><?php _e('In your Auth0 Dashboard, configure your application with these settings:', 'simple-auth0'); ?></p>
        <ul>
            <li><strong><?php _e('Allowed Callback URLs:', 'simple-auth0'); ?></strong> <code><?php echo esc_html(home_url('/wp-json/simple-auth0/v1/callback')); ?></code></li>
            <li><strong><?php _e('Allowed Logout URLs:', 'simple-auth0'); ?></strong> <code><?php echo esc_html(home_url('/wp-login.php')); ?></code>, <code><?php echo esc_html(home_url('/')); ?></code></li>
            <li><strong><?php _e('Allowed Web Origins:', 'simple-auth0'); ?></strong> <code><?php echo esc_html(home_url()); ?></code></li>
            <li><strong><?php _e('Application Type:', 'simple-auth0'); ?></strong> <?php _e('Regular Web Application', 'simple-auth0'); ?></li>
        </ul>
    </div>

    <div class="help-section">
        <h3><?php _e('2. Plugin Configuration', 'simple-auth0'); ?></h3>
        <ol>
            <li><?php _e('Go to the Settings tab above', 'simple-auth0'); ?></li>
            <li><?php _e('Enter your Auth0 Domain and Client ID', 'simple-auth0'); ?></li>
            <li><?php _e('Enter your Client Secret', 'simple-auth0'); ?></li>
            <li><?php _e('Test the connection using the status badge', 'simple-auth0'); ?></li>
            <li><?php _e('Enable Auth0 Login when ready', 'simple-auth0'); ?></li>
        </ol>
    </div>

    <div class="help-section">
        <h3><?php _e('3. User Migration', 'simple-auth0'); ?></h3>
        <p><?php _e('Use the Sync tab to export your WordPress users for import into Auth0. The export will be in Auth0\'s bulk import format.', 'simple-auth0'); ?></p>
    </div>

    <div class="help-section">
        <h3><?php _e('4. Troubleshooting', 'simple-auth0'); ?></h3>
        <ul>
            <li><?php _e('Make sure your Auth0 domain is correctly formatted (e.g., your-tenant.auth0.com)', 'simple-auth0'); ?></li>
            <li><?php _e('Verify that callback URLs are exactly as shown above', 'simple-auth0'); ?></li>
            <li><?php _e('Check that your Auth0 application is set to "Regular Web Application" type', 'simple-auth0'); ?></li>
            <li><?php _e('Ensure your WordPress site is accessible from the internet for Auth0 callbacks', 'simple-auth0'); ?></li>
            <li><?php _e('Check your WordPress error logs for any PHP errors', 'simple-auth0'); ?></li>
            <li><?php _e('Verify that your Auth0 application is not in a locked state', 'simple-auth0'); ?></li>
        </ul>
    </div>

    <div class="help-section">
        <h3><?php _e('5. Security Considerations', 'simple-auth0'); ?></h3>
        <ul>
            <li><?php _e('Keep your Client Secret secure and never share it publicly', 'simple-auth0'); ?></li>
            <li><?php _e('Use HTTPS for your WordPress site in production', 'simple-auth0'); ?></li>
            <li><?php _e('Regularly review your Auth0 application settings', 'simple-auth0'); ?></li>
            <li><?php _e('Monitor your Auth0 logs for suspicious activity', 'simple-auth0'); ?></li>
        </ul>
    </div>

    <div class="help-section">
        <h3><?php _e('6. Support', 'simple-auth0'); ?></h3>
        <p><?php _e('For additional help:', 'simple-auth0'); ?></p>
        <ul>
            <li><?php _e('Check the Auth0 documentation:', 'simple-auth0'); ?> <a href="https://auth0.com/docs" target="_blank">https://auth0.com/docs</a></li>
            <li><?php _e('WordPress Codex:', 'simple-auth0'); ?> <a href="https://codex.wordpress.org/" target="_blank">https://codex.wordpress.org/</a></li>
            <li><?php _e('Plugin support:', 'simple-auth0'); ?> <a href="https://github.com/your-repo/simple-auth0/issues" target="_blank">GitHub Issues</a></li>
        </ul>
    </div>
</div>