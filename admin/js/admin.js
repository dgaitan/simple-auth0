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
            
            // Form validation
            $(document).on('submit', 'form', this.validateForm.bind(this));
            
            // Real-time validation
            $(document).on('blur', '#simple_auth0_domain', this.validateDomain.bind(this));
            $(document).on('blur', '#simple_auth0_client_id', this.validateClientId.bind(this));
            $(document).on('blur', '#simple_auth0_client_secret', this.validateClientSecret.bind(this));
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
                timeout: 30000, // 30 second timeout
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
                    if (status === 'timeout') {
                        SimpleAuth0Admin.showStatusMessage('error', 'Connection test timed out. Please try again.');
                    } else {
                        SimpleAuth0Admin.showStatusMessage('error', 'Network error: ' + error);
                    }
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
        },

        /**
         * Validate form before submission
         */
        validateForm: function(e) {
            var isValid = true;
            var $form = $(e.target);
            
            // Clear previous validation messages
            $('.validation-error').remove();
            $('.form-table input').removeClass('error');
            
            // Validate domain
            if (!this.validateDomain()) {
                isValid = false;
            }
            
            // Validate client ID
            if (!this.validateClientId()) {
                isValid = false;
            }
            
            // Validate client secret if provided
            var $clientSecret = $('#simple_auth0_client_secret');
            if ($clientSecret.val().length > 0 && !this.validateClientSecret()) {
                isValid = false;
            }
            
            if (!isValid) {
                e.preventDefault();
                SimpleAuth0Admin.showStatusMessage('error', 'Please fix the validation errors before saving.');
            }
        },

        /**
         * Validate Auth0 domain
         */
        validateDomain: function() {
            var $field = $('#simple_auth0_domain');
            var domain = $field.val().trim();
            
            if (domain.length === 0) {
                return true; // Optional field
            }
            
            // More flexible pattern to handle various Auth0 domain formats
            var pattern = /^[a-zA-Z0-9][a-zA-Z0-9-]*[a-zA-Z0-9]*\.(auth0\.com|us\.auth0\.com|eu\.auth0\.com|au\.auth0\.com|dev\.auth0\.com)$/;
            
            // Also allow domains that just end with .auth0.com (for custom domains)
            if (!pattern.test(domain) && !/^[a-zA-Z0-9][a-zA-Z0-9-]*[a-zA-Z0-9]*\.auth0\.com$/.test(domain)) {
                this.showFieldError($field, 'Please enter a valid Auth0 domain (e.g., your-tenant.auth0.com)');
                return false;
            }
            
            this.clearFieldError($field);
            return true;
        },

        /**
         * Validate Client ID
         */
        validateClientId: function() {
            var $field = $('#simple_auth0_client_id');
            var clientId = $field.val().trim();
            
            if (clientId.length === 0) {
                return true; // Optional field
            }
            
            if (clientId.length < 10) {
                this.showFieldError($field, 'Client ID must be at least 10 characters long');
                return false;
            }
            
            this.clearFieldError($field);
            return true;
        },

        /**
         * Validate Client Secret
         */
        validateClientSecret: function() {
            var $field = $('#simple_auth0_client_secret');
            var clientSecret = $field.val().trim();
            
            if (clientSecret.length === 0) {
                return true; // Optional field
            }
            
            if (clientSecret.length < 20) {
                this.showFieldError($field, 'Client Secret must be at least 20 characters long');
                return false;
            }
            
            this.clearFieldError($field);
            return true;
        },

        /**
         * Show field validation error
         */
        showFieldError: function($field, message) {
            $field.addClass('error');
            $field.after('<div class="validation-error" style="color: #dc3545; font-size: 12px; margin-top: 5px;">' + message + '</div>');
        },

        /**
         * Clear field validation error
         */
        clearFieldError: function($field) {
            $field.removeClass('error');
            $field.siblings('.validation-error').remove();
        }
    };

})(jQuery);
