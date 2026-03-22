<?php
/**
 * Site lifecycle handling.
 *
 * @package securekey-login
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class Passkey_Login_Site_Manager {
	/**
	 * Initialize hooks.
	 *
	 * @return void
	 */
	public function init(): void {
		if ( is_multisite() ) {
			add_action( 'wp_initialize_site', array( $this, 'on_site_initialize' ), 20, 1 );
		}
	}

	/**
	 * Create tables for new site.
	 *
	 * @param WP_Site $new_site Site object.
	 * @return void
	 */
	public function on_site_initialize( WP_Site $new_site ): void {
		$network_settings = Passkey_Login_Settings::network_settings();
		if ( '1' !== (string) $network_settings['auto_provision_new_sites'] ) {
			return;
		}

		switch_to_blog( (int) $new_site->blog_id );
		Passkey_Login_Installer::create_site_tables();
		Passkey_Login_Settings::ensure_defaults();
		restore_current_blog();
	}
}
