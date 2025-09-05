<?php
/**
 * Test Story #1: Install without takeover
 *
 * @package SimpleAuth0
 */

// Prevent direct access
if (!defined('ABSPATH')) {
    exit;
}

/**
 * Test class for Story #1
 */
class Test_Story1 {

    /**
     * Test that enable_auth0_login defaults to false
     */
    public function test_enable_auth0_login_defaults_to_false() {
        // Get the default options
        $default_options = get_option('simple_auth0_options', []);
        
        // Assert that enable_auth0_login is false
        assert(
            empty($default_options['enable_auth0_login']),
            'enable_auth0_login should default to false'
        );
        
        echo "✅ enable_auth0_login defaults to false\n";
    }

    /**
     * Test that wp-login.php works normally after activation
     */
    public function test_wp_login_works_normally() {
        // Check that no Auth0 redirect hooks are active
        $has_login_init_hook = has_action('login_init', 'SimpleAuth0\Simple_Auth0::redirect_to_auth0');
        $has_authenticate_hook = has_filter('authenticate', 'SimpleAuth0\Simple_Auth0::authenticate_user');
        $has_login_url_hook = has_filter('login_url', 'SimpleAuth0\Simple_Auth0::modify_login_url');
        
        // These hooks should not be active when Auth0 login is disabled
        assert(
            !$has_login_init_hook,
            'login_init hook should not be active when Auth0 login is disabled'
        );
        
        assert(
            !$has_authenticate_hook,
            'authenticate hook should not be active when Auth0 login is disabled'
        );
        
        assert(
            !$has_login_url_hook,
            'login_url hook should not be active when Auth0 login is disabled'
        );
        
        echo "✅ wp-login.php works normally (no Auth0 hooks active)\n";
    }

    /**
     * Test that no Auth0 redirects occur when disabled
     */
    public function test_no_auth0_redirects_when_disabled() {
        // Get plugin instance
        $plugin = SimpleAuth0\Simple_Auth0::get_instance();
        
        // Check that is_auth0_login_enabled returns false
        assert(
            !$plugin->is_auth0_login_enabled(),
            'is_auth0_login_enabled should return false by default'
        );
        
        echo "✅ No Auth0 redirects occur when disabled\n";
    }

    /**
     * Test plugin activation behavior
     */
    public function test_plugin_activation_behavior() {
        // Check that options are properly set
        $options = get_option('simple_auth0_options', []);
        
        // Required fields should be present
        assert(
            isset($options['enable_auth0_login']),
            'enable_auth0_login option should be set'
        );
        
        assert(
            isset($options['redirect_uri']),
            'redirect_uri option should be set'
        );
        
        assert(
            isset($options['scopes']),
            'scopes option should be set'
        );
        
        // Default values should be correct
        assert(
            $options['enable_auth0_login'] === false,
            'enable_auth0_login should be false'
        );
        
        assert(
            $options['scopes'] === 'openid profile email',
            'scopes should have correct default value'
        );
        
        echo "✅ Plugin activation behavior is correct\n";
    }

    /**
     * Test that REST API routes are registered
     */
    public function test_rest_api_routes_registered() {
        // Check that REST API routes are registered
        $routes = rest_get_server()->get_routes();
        
        assert(
            isset($routes['/simple-auth0/v1/callback']),
            'OAuth callback route should be registered'
        );
        
        assert(
            isset($routes['/simple-auth0/v1/logout']),
            'Logout route should be registered'
        );
        
        echo "✅ REST API routes are properly registered\n";
    }

    /**
     * Run all tests
     */
    public function run_all_tests() {
        echo "🧪 Running Story #1 Tests...\n\n";
        
        try {
            $this->test_enable_auth0_login_defaults_to_false();
            $this->test_wp_login_works_normally();
            $this->test_no_auth0_redirects_when_disabled();
            $this->test_plugin_activation_behavior();
            $this->test_rest_api_routes_registered();
            
            echo "\n🎉 All Story #1 tests passed!\n";
            echo "✅ Plugin is non-invasive by default\n";
            echo "✅ WordPress login works normally\n";
            echo "✅ No Auth0 redirects occur until enabled\n";
            
        } catch (AssertionError $e) {
            echo "\n❌ Test failed: " . $e->getMessage() . "\n";
            return false;
        }
        
        return true;
    }
}

// Run tests if this file is accessed directly
if (defined('WP_CLI') && WP_CLI) {
    $test = new Test_Story1();
    $test->run_all_tests();
}
