/**
 * Simple Auth0 Admin JavaScript
 */

(function($) {
    'use strict';

    // Initialize when document is ready
    $(document).ready(function() {
        SimpleAuth0Admin.init();
    });

    // Main admin object
    window.SimpleAuth0Admin = {
        
        /**
         * Initialize admin functionality
         */
        init: function() {
            this.bindEvents();
            this.checkConnectionStatus();
        },

        /**
         * Bind event handlers
         */
        bindEvents: function() {
            // Test connection button
            $(document).on('click', '#test-connection', this.testConnection.bind(this));
            
            // Preview export button
            $(document).on('click', '#preview-export', this.previewExport.bind(this));
            
            // Download export button
            $(document).on('click', '#download-export', this.downloadExport.bind(this));
        },

        /**
         * Check initial connection status
         */
        checkConnectionStatus: function() {
            const statusBadge = $('#connection-status');
            if (statusBadge.length) {
                this.updateStatusBadge('checking', 'Checking connection...');
                this.testConnection();
            }
        },

        /**
         * Test Auth0 connection
         */
        testConnection: function(e) {
            if (e) {
                e.preventDefault();
            }

            const $button = $('#test-connection');
            const $statusBadge = $('#connection-status');
            
            // Disable button and show loading state
            $button.prop('disabled', true).text('Testing...');
            this.updateStatusBadge('checking', 'Testing connection...');

            // Make AJAX request
            $.ajax({
                url: ajaxurl,
                type: 'POST',
                data: {
                    action: 'simple_auth0_test_connection',
                    nonce: simple_auth0_admin.nonce
                },
                success: function(response) {
                    if (response.success) {
                        SimpleAuth0Admin.updateStatusBadge('connected', 'Connected to Auth0');
                        SimpleAuth0Admin.showStatusMessage('success', response.data.message || 'Connection successful!');
                    } else {
                        SimpleAuth0Admin.updateStatusBadge('not-connected', 'Connection failed');
                        SimpleAuth0Admin.showStatusMessage('error', response.data.message || 'Connection failed. Please check your settings.');
                    }
                },
                error: function(xhr, status, error) {
                    SimpleAuth0Admin.updateStatusBadge('not-connected', 'Connection failed');
                    SimpleAuth0Admin.showStatusMessage('error', 'Network error: ' + error);
                },
                complete: function() {
                    $button.prop('disabled', false).text('Test Connection');
                }
            });
        },

        /**
         * Update status badge
         */
        updateStatusBadge: function(status, text) {
            const $badge = $('#connection-status');
            $badge.removeClass('connected not-connected checking')
                  .addClass(status);
            $badge.find('.status-text').text(text);
        },

        /**
         * Show status message
         */
        showStatusMessage: function(type, message) {
            // Remove existing messages
            $('.status-message').remove();
            
            // Create new message
            const $message = $('<div class="status-message ' + type + '">' + message + '</div>');
            
            // Insert after status card
            $('.simple-auth0-status-card').after($message);
            
            // Auto-hide after 5 seconds
            setTimeout(function() {
                $message.fadeOut(function() {
                    $(this).remove();
                });
            }, 5000);
        },

        /**
         * Preview user export
         */
        previewExport: function(e) {
            e.preventDefault();
            
            const $button = $(e.target);
            const $preview = $('#export-preview');
            const $content = $('#preview-content');
            
            $button.prop('disabled', true).text('Generating...');
            
            $.ajax({
                url: ajaxurl,
                type: 'POST',
                data: {
                    action: 'simple_auth0_preview_export',
                    nonce: simple_auth0_admin.nonce
                },
                success: function(response) {
                    if (response.success) {
                        $content.text(JSON.stringify(response.data, null, 2));
                        $preview.show();
                        SimpleAuth0Admin.showStatusMessage('success', 'Export preview generated successfully!');
                    } else {
                        SimpleAuth0Admin.showStatusMessage('error', response.data.message || 'Failed to generate preview.');
                    }
                },
                error: function(xhr, status, error) {
                    SimpleAuth0Admin.showStatusMessage('error', 'Network error: ' + error);
                },
                complete: function() {
                    $button.prop('disabled', false).text('Preview Export');
                }
            });
        },

        /**
         * Download user export
         */
        downloadExport: function(e) {
            e.preventDefault();
            
            const $button = $(e.target);
            $button.prop('disabled', true).text('Generating...');
            
            $.ajax({
                url: ajaxurl,
                type: 'POST',
                data: {
                    action: 'simple_auth0_download_export',
                    nonce: simple_auth0_admin.nonce
                },
                success: function(response) {
                    if (response.success) {
                        // Create download link
                        const blob = new Blob([JSON.stringify(response.data, null, 2)], {type: 'application/json'});
                        const url = window.URL.createObjectURL(blob);
                        const a = document.createElement('a');
                        a.href = url;
                        a.download = 'auth0-users-export.json';
                        document.body.appendChild(a);
                        a.click();
                        document.body.removeChild(a);
                        window.URL.revokeObjectURL(url);
                        
                        SimpleAuth0Admin.showStatusMessage('success', 'Export downloaded successfully!');
                    } else {
                        SimpleAuth0Admin.showStatusMessage('error', response.data.message || 'Failed to generate export.');
                    }
                },
                error: function(xhr, status, error) {
                    SimpleAuth0Admin.showStatusMessage('error', 'Network error: ' + error);
                },
                complete: function() {
                    $button.prop('disabled', false).text('Download Export');
                }
            });
        }
    };

})(jQuery);
