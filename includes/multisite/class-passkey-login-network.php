<?php
/**
 * Multisite network manager.
 *
 * @package securekey-login
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class Passkey_Login_Network {
	/**
	 * Initialize multisite hooks.
	 *
	 * @return void
	 */
	public function init(): void {
		$site_manager = new Passkey_Login_Site_Manager();
		$user_sync    = new Passkey_Login_User_Sync();

		$site_manager->init();
		$user_sync->init();
	}

	/**
	 * Resolve WebAuthn RP ID.
	 *
	 * @return string
	 */
	public function get_rp_id(): string {
		$override = (string) Passkey_Login_Settings::get( 'rp_id_override' );
		$override = sanitize_text_field( (string) $override );
		if ( '' !== $override ) {
			return $override;
		}

		$network_url = is_multisite() ? network_home_url() : home_url();
		$host        = (string) wp_parse_url( $network_url, PHP_URL_HOST );

		if ( '' === $host ) {
			$host = (string) wp_parse_url( home_url(), PHP_URL_HOST );
		}

		// RP ID must be an effective registrable domain, not a specific subsite host.
		if ( is_multisite() ) {
			$parts = explode( '.', $host );
			if ( count( $parts ) > 2 ) {
				$host = implode( '.', array_slice( $parts, -2 ) );
			}
		}

		return strtolower( $host );
	}
}
