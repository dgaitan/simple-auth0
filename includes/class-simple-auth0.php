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
}
