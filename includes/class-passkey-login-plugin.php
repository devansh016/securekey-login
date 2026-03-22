<?php
/**
 * Plugin bootstrap class.
 *
 * @package securekey-login
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class Passkey_Login_Plugin {
	/**
	 * Initialize plugin.
	 *
	 * @return void
	 */
	public function init(): void {
		Passkey_Login_Settings::ensure_defaults();

		$network = new Passkey_Login_Network();
		$network->init();

		$admin = new Passkey_Login_Admin();
		$admin->init();

		$network_admin = new Passkey_Login_Network_Admin();
		$network_admin->init();

		$user_profile = new Passkey_Login_User_Profile();
		$user_profile->init();

		$login_form = new Passkey_Login_Login_Form();
		$login_form->init();

		$shortcodes = new Passkey_Login_Shortcodes();
		$shortcodes->init();

		$api = new Passkey_Login_REST_API();
		$api->init();

		$authenticator = new Passkey_Login_Authenticator();
		$authenticator->init();
	}
}
