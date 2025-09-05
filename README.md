# Simple Auth0 WordPress Plugin

A WordPress plugin that integrates Auth0 authentication and can optionally replace the native WordPress login flow.

## Features

- **Non-invasive by default**: WordPress continues using its own login until explicitly enabled
- **OAuth 2.0 + PKCE**: Secure authentication flow using Auth0
- **User synchronization**: Export existing WordPress users to Auth0
- **Auto-sync**: Automatically sync new/updated WordPress users to Auth0
- **Admin dashboard**: Easy configuration through WordPress admin
- **REST API integration**: OAuth callback handling via WordPress REST API

## Requirements

- WordPress 6.4+
- PHP 8.1+
- Composer
- Auth0 account and application

## Installation

1. Clone or download this plugin to your WordPress plugins directory
2. Navigate to the plugin directory and run `composer install`
3. Activate the plugin in WordPress admin
4. Configure your Auth0 settings in **Settings → Simple Auth0**

## Configuration

### Auth0 Application Setup

1. Create a new application in your Auth0 dashboard
2. Set the application type to "Regular Web Application"
3. Configure the following URLs:
   - **Allowed Callback URLs**: `https://yoursite.com/wp-json/simple-auth0/v1/callback`
   - **Allowed Logout URLs**: `https://yoursite.com/wp-login.php`, `https://yoursite.com/`
   - **Allowed Web Origins**: `https://yoursite.com`

### Plugin Settings

Configure the following in **Settings → Simple Auth0**:

- **Auth0 Domain**: Your Auth0 tenant domain
- **Client ID**: Your Auth0 application client ID
- **Client Secret**: Your Auth0 application client secret
- **Audience**: (Optional) API audience for API access
- **Redirect URI**: OAuth callback URL (auto-generated)
- **Scopes**: OAuth scopes (default: openid profile email)
- **Enable Auth0 Login**: Toggle to replace WordPress login with Auth0

## Development

### Setup

```bash
# Install dependencies
composer install

# Run tests
composer test

# Generate test coverage
composer test-coverage
```

### Project Structure

```text
simple-auth0/
├── admin/                 # Admin interface
│   ├── css/              # Admin styles
│   └── class-admin.php   # Admin functionality
├── includes/             # Core plugin classes
│   └── class-simple-auth0.php
├── rest-api/             # REST API handlers
│   └── class-oauth-handler.php
├── docs/                 # Documentation
├── tests/                # Unit tests
├── vendor/               # Composer dependencies
├── composer.json         # Composer configuration
├── simple-auth0.php      # Main plugin file
└── README.md
```

## Security

- Client secrets are stored encrypted when possible
- All form submissions use WordPress nonces
- OAuth state and nonce validation
- PKCE (Proof Key for Code Exchange) for enhanced security
- Capability checks for admin functions

## License

GPL v2 or later

## Support

For issues and feature requests, please visit the [GitHub repository](https://github.com/your-username/simple-auth0).
