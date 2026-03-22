<?php
/**
 * Capabilities manager.
 *
 * @package securekey-login
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class Passkey_Login_Capabilities {
	/**
	 * Register plugin capabilities.
	 *
	 * @return void
	 */
	public static function register(): void {
		$roles = array( 'administrator' );

		foreach ( $roles as $role_name ) {
			$role = get_role( $role_name );
			if ( $role instanceof WP_Role ) {
				$role->add_cap( 'securekey_login_manage_passkeys' );
				$role->add_cap( 'securekey_login_manage_network_passkeys' );
			}
		}
	}

	/**
	 * Remove plugin capabilities.
	 *
	 * @return void
	 */
	public static function unregister(): void {
		$roles = array( 'administrator' );

		foreach ( $roles as $role_name ) {
			$role = get_role( $role_name );
			if ( $role instanceof WP_Role ) {
				$role->remove_cap( 'securekey_login_manage_passkeys' );
				$role->remove_cap( 'securekey_login_manage_network_passkeys' );
			}
		}
	}
}
