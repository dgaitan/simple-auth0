<?php

/**
 * OAuth handler for Auth0 integration
 *
 * @package SimpleAuth0
 */

namespace SimpleAuth0;

use Auth0\SDK\Auth0;
use Auth0\SDK\Configuration\SdkConfiguration;
use Auth0\SDK\Token\Generator;

// Prevent direct access
if (!defined('ABSPATH')) {
    exit;
}

/**
 * OAuth handler class
 */
class OAuth_Handler
{

    /**
     * Auth0 SDK instance
     *
     * @var Auth0
     */
    private $auth0;

    /**
     * Plugin instance
     *
     * @var Simple_Auth0
     */
    private $plugin;

    /**
     * Constructor
     */
    public function __construct()
    {
        $this->plugin = Simple_Auth0::get_instance();
        $this->init_auth0();
    }

    /**
     * Initialize Auth0 SDK
     */
    private function init_auth0()
    {
        $options = $this->plugin->get_options();

        if (empty($options['domain']) || empty($options['client_id'])) {
            return;
        }

        $configuration = new SdkConfiguration([
            'domain' => $options['domain'],
            'clientId' => $options['client_id'],
            'clientSecret' => $options['client_secret'],
            'redirectUri' => $options['redirect_uri'],
            'audience' => $options['audience'] ?? null,
            'scope' => $options['scopes'] ?? 'openid profile email',
        ]);

        $this->auth0 = new Auth0($configuration);
    }

    /**
     * Handle OAuth callback
     *
     * @param \WP_REST_Request $request REST request object.
     * @return \WP_REST_Response
     */
    public function handle_oauth_callback($request)
    {
        try {
            if (!$this->auth0) {
                return new \WP_REST_Response([
                    'error' => 'Auth0 not configured'
                ], 400);
            }

            // Exchange code for tokens
            $this->auth0->exchange();

            // Get user info
            $user_info = $this->auth0->getUser();

            if (!$user_info) {
                return new \WP_REST_Response([
                    'error' => 'Failed to get user info'
                ], 400);
            }

            // Find or create WordPress user
            $wp_user = $this->find_or_create_user($user_info);

            if (!$wp_user) {
                return new \WP_REST_Response([
                    'error' => 'Failed to create or find user'
                ], 400);
            }

            // Log in the user
            wp_set_current_user($wp_user->ID);
            wp_set_auth_cookie($wp_user->ID);

            // Redirect to intended destination
            $redirect_url = $request->get_param('redirect_to') ?: admin_url();

            return new \WP_REST_Response([
                'success' => true,
                'redirect_url' => $redirect_url
            ], 200);
        } catch (\Exception $e) {
            error_log('Auth0 OAuth callback error: ' . $e->getMessage());

            return new \WP_REST_Response([
                'error' => 'Authentication failed'
            ], 400);
        }
    }

    /**
     * Find or create WordPress user
     *
     * @param array $user_info Auth0 user info.
     * @return \WP_User|false
     */
    private function find_or_create_user($user_info)
    {
        $email = $user_info['email'] ?? '';
        $sub = $user_info['sub'] ?? '';

        if (empty($email)) {
            return false;
        }

        // Try to find existing user by email
        $user = get_user_by('email', $email);

        if ($user) {
            // Update user meta with Auth0 sub
            update_user_meta($user->ID, 'auth0_sub', $sub);
            return $user;
        }

        // Create new user
        $username = $this->generate_username($user_info);
        $user_data = [
            'user_login' => $username,
            'user_email' => $email,
            'user_pass' => wp_generate_password(),
            'first_name' => $user_info['given_name'] ?? '',
            'last_name' => $user_info['family_name'] ?? '',
            'role' => 'subscriber',
        ];

        $user_id = wp_insert_user($user_data);

        if (is_wp_error($user_id)) {
            return false;
        }

        // Store Auth0 sub
        update_user_meta($user_id, 'auth0_sub', $sub);

        return get_user_by('id', $user_id);
    }

    /**
     * Generate username from user info
     *
     * @param array $user_info Auth0 user info.
     * @return string
     */
    private function generate_username($user_info)
    {
        $email = $user_info['email'] ?? '';
        $name = $user_info['name'] ?? '';

        if ($name) {
            $username = sanitize_user($name);
        } else {
            $username = sanitize_user($email);
        }

        // Ensure username is unique
        $original_username = $username;
        $counter = 1;

        while (username_exists($username)) {
            $username = $original_username . $counter;
            $counter++;
        }

        return $username;
    }

    /**
     * Handle logout
     *
     * @param \WP_REST_Request $request REST request object.
     * @return \WP_REST_Response
     */
    public function handle_logout($request)
    {
        // Clear WordPress session
        wp_logout();

        // Get logout URL from Auth0
        $options = $this->plugin->get_options();
        $logout_url = $options['logout_redirect_uri'] ?: home_url();

        if ($this->auth0) {
            $auth0_logout_url = $this->auth0->logout($logout_url);
        } else {
            $auth0_logout_url = $logout_url;
        }

        return new \WP_REST_Response([
            'logout_url' => $auth0_logout_url
        ], 200);
    }
}
