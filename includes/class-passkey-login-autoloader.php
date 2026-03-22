<?php
/**
 * Autoloader.
 *
 * @package securekey-login
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class Passkey_Login_Autoloader {
	/**
	 * Register the autoloader.
	 *
	 * @return void
	 */
	public static function register(): void {
		spl_autoload_register( array( __CLASS__, 'autoload' ) );
	}

	/**
	 * Autoload plugin classes.
	 *
	 * @param string $class Class name.
	 * @return void
	 */
	public static function autoload( string $class ): void {
		if ( 0 !== strpos( $class, 'Passkey_Login_' ) ) {
			return;
		}

		$file = strtolower( str_replace( '_', '-', $class ) );
		$path = PASSKEY_LOGIN_PLUGIN_DIR . 'includes/class-' . $file . '.php';

		if ( file_exists( $path ) ) {
			require_once $path;
			return;
		}

		$groups = array( 'auth', 'multisite', 'admin', 'frontend', 'api', 'utils' );
		foreach ( $groups as $group ) {
			$group_path = PASSKEY_LOGIN_PLUGIN_DIR . 'includes/' . $group . '/class-' . $file . '.php';
			if ( file_exists( $group_path ) ) {
				require_once $group_path;
				return;
			}
		}
	}
}
