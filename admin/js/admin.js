/**
 * Simple Auth0 Admin JavaScript
 */
(function($) {
    'use strict';

    $(document).ready(function() {
        // Initialize admin functionality
        initConnectionCheck();
        initSyncActions();
        initFormValidation();
    });

    /**
     * Initialize connection check functionality
     */
    function initConnectionCheck() {
        // Check connection on page load
        checkConnection();

        // Handle manual connection check
        $('#check-connection').on('click', function(e) {
            e.preventDefault();
            checkConnection();
        });
    }

    /**
     * Check Auth0 connection
     */
    function checkConnection() {
        var $status = $('#connection-status');
        var $button = $('#check-connection');
        
        // Update UI to show checking state
        $status.removeClass('status-connected status-not-connected status-unknown')
               .addClass('status-unknown')
               .text(simpleAuth0.strings.checking);
        
        $button.prop('disabled', true);

        // Make AJAX request
        $.ajax({
            url: simpleAuth0.ajaxUrl,
            type: 'POST',
            data: {
                action: 'simple_auth0_check_connection',
                nonce: simpleAuth0.nonce
            },
            success: function(response) {
                if (response.success) {
                    $status.removeClass('status-unknown status-not-connected')
                           .addClass('status-connected')
                           .text(simpleAuth0.strings.connected);
                } else {
                    $status.removeClass('status-unknown status-connected')
                           .addClass('status-not-connected')
                           .text(simpleAuth0.strings.notConnected + ': ' + (response.data.message || 'Unknown error'));
                }
            },
            error: function() {
                $status.removeClass('status-unknown status-connected')
                       .addClass('status-not-connected')
                       .text(simpleAuth0.strings.notConnected + ': ' + simpleAuth0.strings.error);
            },
            complete: function() {
                $button.prop('disabled', false);
            }
        });
    }

    /**
     * Initialize sync actions
     */
    function initSyncActions() {
        // Preview export
        $('#preview-export').on('click', function(e) {
            e.preventDefault();
            previewExport();
        });

        // Download export
        $('#download-export').on('click', function(e) {
            e.preventDefault();
            downloadExport();
        });
    }

    /**
     * Preview user export
     */
    function previewExport() {
        var $preview = $('#sync-preview');
        var $content = $('#preview-content');
        var $button = $('#preview-export');
        
        $button.prop('disabled', true).text('Loading...');

        $.ajax({
            url: simpleAuth0.ajaxUrl,
            type: 'POST',
            data: {
                action: 'simple_auth0_export_users',
                action_type: 'preview',
                nonce: simpleAuth0.nonce
            },
            success: function(response) {
                if (response.success) {
                    $content.text(response.data.preview);
                    $preview.show();
                } else {
                    alert('Error: ' + (response.data.message || 'Unknown error'));
                }
            },
            error: function() {
                alert('Error: Failed to load preview');
            },
            complete: function() {
                $button.prop('disabled', false).text('Preview Export');
            }
        });
    }

    /**
     * Download user export
     */
    function downloadExport() {
        var $button = $('#download-export');
        
        $button.prop('disabled', true).text('Preparing...');

        // Create a form to submit the download request
        var $form = $('<form>', {
            method: 'POST',
            action: simpleAuth0.ajaxUrl,
            target: '_blank'
        });

        $form.append($('<input>', {
            type: 'hidden',
            name: 'action',
            value: 'simple_auth0_export_users'
        }));

        $form.append($('<input>', {
            type: 'hidden',
            name: 'action_type',
            value: 'download'
        }));

        $form.append($('<input>', {
            type: 'hidden',
            name: 'nonce',
            value: simpleAuth0.nonce
        }));

        $('body').append($form);
        $form.submit();
        $form.remove();

        // Reset button after a delay
        setTimeout(function() {
            $button.prop('disabled', false).text('Download JSON');
        }, 2000);
    }

    /**
     * Initialize form validation
     */
    function initFormValidation() {
        // Real-time validation for required fields
        $('input[required]').on('blur', function() {
            validateField($(this));
        });

        // Form submission validation
        $('form').on('submit', function(e) {
            var isValid = true;
            var $form = $(this);
            
            $form.find('input[required]').each(function() {
                if (!validateField($(this))) {
                    isValid = false;
                }
            });

            if (!isValid) {
                e.preventDefault();
                alert('Please fill in all required fields correctly.');
            }
        });
    }

    /**
     * Validate individual field
     */
    function validateField($field) {
        var value = $field.val().trim();
        var isValid = true;
        var $fieldContainer = $field.closest('td');

        // Remove existing error styling
        $field.removeClass('error');
        $fieldContainer.find('.field-error').remove();

        // Check if required field is empty
        if ($field.prop('required') && !value) {
            isValid = false;
            showFieldError($field, 'This field is required.');
        }

        // Validate URL fields
        if ($field.attr('type') === 'url' && value) {
            var urlPattern = /^https?:\/\/.+/;
            if (!urlPattern.test(value)) {
                isValid = false;
                showFieldError($field, 'Please enter a valid URL.');
            }
        }

        // Validate email fields
        if ($field.attr('type') === 'email' && value) {
            var emailPattern = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
            if (!emailPattern.test(value)) {
                isValid = false;
                showFieldError($field, 'Please enter a valid email address.');
            }
        }

        return isValid;
    }

    /**
     * Show field error
     */
    function showFieldError($field, message) {
        $field.addClass('error');
        $field.closest('td').append('<div class="field-error" style="color: #dc3232; font-size: 12px; margin-top: 5px;">' + message + '</div>');
    }

    /**
     * Tab functionality (if needed for future enhancements)
     */
    function initTabs() {
        $('.nav-tab').on('click', function(e) {
            e.preventDefault();
            
            // Remove active class from all tabs
            $('.nav-tab').removeClass('nav-tab-active');
            
            // Add active class to clicked tab
            $(this).addClass('nav-tab-active');
            
            // Handle tab content switching if needed
            // (Currently handled by server-side rendering)
        });
    }

})(jQuery);
