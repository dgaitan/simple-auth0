<?php
/**
 * Admin page template
 * 
 * @var string $page_title
 * @var array $tabs
 * @var string $current_tab
 * @var string $tab_content
 */

if (!defined('ABSPATH')) {
    exit;
}
?>

<div class="wrap simple-auth0-admin">
    <div class="simple-auth0-header">
        <h1><?php echo esc_html($page_title); ?></h1>
        <p><?php _e('Secure authentication with Auth0 integration for your WordPress site', 'simple-auth0'); ?></p>
    </div>
    
    <div class="simple-auth0-status-card">
        <h3><?php _e('Connection Status', 'simple-auth0'); ?></h3>
        <div style="display: flex; align-items: center; flex-wrap: wrap;">
            <span class="status-badge" id="connection-status">
                <span class="status-indicator"></span>
                <span class="status-text"><?php _e('Checking connection...', 'simple-auth0'); ?></span>
            </span>
            <button type="button" class="test-connection-btn" id="test-connection">
                <?php _e('Test Connection', 'simple-auth0'); ?>
            </button>
        </div>
    </div>
    
    <div class="simple-auth0-tabs">
        <nav class="nav-tab-wrapper wp-clearfix">
            <?php foreach ($tabs as $tab_key => $tab_label) : ?>
                <a href="<?php echo esc_url(admin_url('options-general.php?page=simple-auth0&tab=' . $tab_key)); ?>"
                    class="nav-tab <?php echo $current_tab === $tab_key ? 'nav-tab-active' : ''; ?>">
                    <?php echo esc_html($tab_label); ?>
                </a>
            <?php endforeach; ?>
        </nav>
        
        <div class="tab-content">
            <?php echo $tab_content; ?>
        </div>
    </div>
</div>
