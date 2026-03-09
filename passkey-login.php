<?php
/**
 * Plugin Name: Passkey Login
 * Plugin URI:  https://wordpress.org/plugins/passkey-login/
 * Description: Passwordless WebAuthn/FIDO2 passkey authentication for WordPress single-site and multisite.
 * Version:     1.0.0
 * Requires at least: 6.3
 * Requires PHP: 8.2
 * Author:      Devansh Chaudhary
 * Author URI:  https://profiles.wordpress.org/devansh2002/
 * License:     GPL-2.0-or-later
 * License URI: https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain: passkey-login
 * Network:     true
 *
 * @package passkey-login
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

if ( version_compare( PHP_VERSION, '8.2', '<' ) ) {
	add_action(
		'admin_notices',
		static function (): void {
			echo '<div class="notice notice-error"><p>' . esc_html__( 'Passkey Login requires PHP 8.2 or newer.', 'passkey-login' ) . '</p></div>';
		}
	);

	return;
}

define( 'PASSKEY_LOGIN_VERSION', '1.0.0' );
define( 'PASSKEY_LOGIN_PLUGIN_FILE', __FILE__ );
define( 'PASSKEY_LOGIN_PLUGIN_DIR', plugin_dir_path( __FILE__ ) );
define( 'PASSKEY_LOGIN_PLUGIN_URL', plugin_dir_url( __FILE__ ) );
define( 'PASSKEY_LOGIN_TEXT_DOMAIN', 'passkey-login' );

require_once PASSKEY_LOGIN_PLUGIN_DIR . 'includes/class-passkey-login-autoloader.php';
require_once PASSKEY_LOGIN_PLUGIN_DIR . 'includes/class-passkey-login-installer.php';

if ( file_exists( PASSKEY_LOGIN_PLUGIN_DIR . 'vendor/autoload.php' ) ) {
	require_once PASSKEY_LOGIN_PLUGIN_DIR . 'vendor/autoload.php';
}

Passkey_Login_Autoloader::register();

register_activation_hook( __FILE__, array( 'Passkey_Login_Installer', 'activate' ) );
register_deactivation_hook( __FILE__, array( 'Passkey_Login_Installer', 'deactivate' ) );

add_action(
	'plugins_loaded',
	static function (): void {
		$plugin = new Passkey_Login_Plugin();
		$plugin->init();
	}
);
