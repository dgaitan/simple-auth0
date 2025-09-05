<?php

/**
 * Sync tab template
 */

if (!defined('ABSPATH')) {
    exit;
}
?>

<div class="simple-auth0-card sync">
    <h2><?php _e('User Sync', 'simple-auth0'); ?></h2>
    <p><?php _e('Export your WordPress users to Auth0-compatible format for easy migration.', 'simple-auth0'); ?></p>

    <div class="sync-actions">
        <button type="button" class="sync-btn secondary" id="preview-export">
            <?php _e('Preview Export', 'simple-auth0'); ?>
        </button>
        <button type="button" class="sync-btn" id="download-export">
            <?php _e('Download Export', 'simple-auth0'); ?>
        </button>
    </div>

    <div id="export-preview" style="display: none;">
        <h3><?php _e('Export Preview', 'simple-auth0'); ?></h3>
        <div class="export-preview">
            <pre id="preview-content"></pre>
        </div>
    </div>

    <div class="help-section">
        <h3><?php _e('Export Information', 'simple-auth0'); ?></h3>
        <ul>
            <li><?php _e('The export includes user email, email verification status, and user ID', 'simple-auth0'); ?></li>
            <li><?php _e('User IDs are prefixed with "wp|" to avoid conflicts with Auth0 users', 'simple-auth0'); ?></li>
            <li><?php _e('Password hashes are included when supported by the WordPress installation', 'simple-auth0'); ?></li>
            <li><?php _e('The export follows Auth0\'s bulk import JSON format', 'simple-auth0'); ?></li>
        </ul>
    </div>

    <div class="help-section">
        <h3><?php _e('Import Instructions', 'simple-auth0'); ?></h3>
        <ol>
            <li><?php _e('Download the export file using the button above', 'simple-auth0'); ?></li>
            <li><?php _e('Go to your Auth0 Dashboard → User Management → Users', 'simple-auth0'); ?></li>
            <li><?php _e('Click "Import Users" and select the downloaded JSON file', 'simple-auth0'); ?></li>
            <li><?php _e('Choose the database connection to import users into', 'simple-auth0'); ?></li>
            <li><?php _e('Review the import settings and start the import', 'simple-auth0'); ?></li>
        </ol>
    </div>
</div>