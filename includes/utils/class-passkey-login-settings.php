<?php
/**
 * Settings helper and defaults.
 *
 * @package securekey-login
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}


class Passkey_Login_Settings {
	/**
	 * Site option key.
	 */
	private const SITE_OPTION = 'securekey_login_settings';

	/**
	 * Network option key.
	 */
	private const NETWORK_OPTION = 'securekey_login_network_settings';

	/**
	 * Get site defaults.
	 *
	 * @return array<string,mixed>
	 */
	public static function site_defaults(): array {
		return array(
			'enable_passkeys'            => '1',
			'show_login_button'          => '1',
			'allow_profile_registration' => '1',
		);
	}

	/**
	 * Get network defaults.
	 *
	 * @return array<string,mixed>
	 */
	public static function network_defaults(): array {
		return array_merge(
			self::site_defaults(),
			array(
				'enforced_roles'           => array(),
				'rp_id_override'           => '',
				'allowed_origins'          => '',
				'allow_site_overrides'     => '1',
				'auto_provision_new_sites' => '1',
			)
		);
	}

	/**
	 * Bootstrap default options.
	 *
	 * @return void
	 */
	public static function ensure_defaults(): void {
		$site = get_option( self::SITE_OPTION, array() );
		if ( ! is_array( $site ) ) {
			$site = array();
		}
		update_option( self::SITE_OPTION, wp_parse_args( $site, self::site_defaults() ) );

		if ( is_multisite() ) {
			$network = get_site_option( self::NETWORK_OPTION, array() );
			if ( ! is_array( $network ) ) {
				$network = array();
			}
			update_site_option( self::NETWORK_OPTION, wp_parse_args( $network, self::network_defaults() ) );
		}
	}

	/**
	 * Sanitize site settings.
	 *
	 * @param mixed $input Input.
	 * @return array<string,mixed>
	 */
	public static function sanitize_site_settings( $input ): array {
		$input  = is_array( $input ) ? $input : array();
		$clean  = self::site_defaults();
		$source = wp_unslash( $input );

		$clean['enable_passkeys']            = self::bool_string( $source['enable_passkeys'] ?? '0' );
		$clean['show_login_button']          = self::bool_string( $source['show_login_button'] ?? '0' );
		$clean['allow_profile_registration'] = self::bool_string( $source['allow_profile_registration'] ?? '0' );

		return $clean;
	}

	/**
	 * Sanitize network settings.
	 *
	 * @param mixed $input Input.
	 * @return array<string,mixed>
	 */
	public static function sanitize_network_settings( $input ): array {
		$input  = is_array( $input ) ? $input : array();
		$base   = self::sanitize_site_settings( $input );
		$source = wp_unslash( $input );

		$roles = array();
		if ( isset( $source['enforced_roles'] ) && is_array( $source['enforced_roles'] ) ) {
			$roles = array_map( 'sanitize_key', $source['enforced_roles'] );
		}

		$base['enforced_roles']           = array_values( array_unique( $roles ) );
		$base['rp_id_override']           = sanitize_text_field( (string) ( $source['rp_id_override'] ?? '' ) );
		$base['allowed_origins']          = self::sanitize_origins( (string) ( $source['allowed_origins'] ?? '' ) );
		$base['allow_site_overrides']     = self::bool_string( $source['allow_site_overrides'] ?? '0' );
		$base['auto_provision_new_sites'] = self::bool_string( $source['auto_provision_new_sites'] ?? '0' );

		return $base;
	}

	/**
	 * Get resolved setting.
	 *
	 * @param string $key Setting key.
	 * @return mixed
	 */
	public static function get( string $key ) {
		if ( is_multisite() ) {
			$network               = self::network_settings();
			$network_enforced_keys = array(
				'enable_passkeys',
				'show_login_button',
				'allow_profile_registration',
			);
			if ( in_array( $key, $network_enforced_keys, true ) ) {
				return $network[ $key ] ?? null;
			}

			if ( ! self::allow_site_overrides() && array_key_exists( $key, $network ) ) {
				return $network[ $key ];
			}
			$site = self::site_settings();
			if ( array_key_exists( $key, $site ) ) {
				return $site[ $key ];
			}
			return $network[ $key ] ?? null;
		}

		$site = self::site_settings();
		return $site[ $key ] ?? null;
	}

	/**
	 * Return site settings.
	 *
	 * @return array<string,mixed>
	 */
	public static function site_settings(): array {
		$settings = get_option( self::SITE_OPTION, array() );
		if ( ! is_array( $settings ) ) {
			$settings = array();
		}
		return wp_parse_args( $settings, self::site_defaults() );
	}

	/**
	 * Return network settings.
	 *
	 * @return array<string,mixed>
	 */
	public static function network_settings(): array {
		$settings = get_site_option( self::NETWORK_OPTION, array() );
		if ( ! is_array( $settings ) ) {
			$settings = array();
		}
		return wp_parse_args( $settings, self::network_defaults() );
	}

	/**
	 * Whether site overrides are allowed.
	 *
	 * @return bool
	 */
	public static function allow_site_overrides(): bool {
		if ( ! is_multisite() ) {
			return true;
		}
		return '1' === (string) self::network_settings()['allow_site_overrides'];
	}

	/**
	 * Check if passkeys are enabled.
	 *
	 * @return bool
	 */
	public static function passkeys_enabled(): bool {
		return '1' === (string) self::get( 'enable_passkeys' );
	}

	/**
	 * Get allowed origins list.
	 *
	 * @return array<int,string>
	 */
	public static function allowed_origins(): array {
		$value = (string) self::get( 'allowed_origins' );
		if ( '' === trim( $value ) ) {
			return array();
		}

		$items = preg_split( '/\r\n|\r|\n/', $value );
		if ( ! is_array( $items ) ) {
			$items = array();
		}
		$origins = array();
		foreach ( $items as $item ) {
			$item = trim( (string) $item );
			if ( '' !== $item ) {
				$origins[] = $item;
			}
		}

		return array_values( array_unique( $origins ) );
	}

	/**
	 * Sanitize multiline origins.
	 *
	 * @param string $value Raw value.
	 * @return string
	 */
	private static function sanitize_origins( string $value ): string {
		$items = preg_split( '/\r\n|\r|\n/', $value );
		if ( ! is_array( $items ) ) {
			$items = array();
		}
		$sanitized = array();
		foreach ( $items as $item ) {
			$item = trim( esc_url_raw( $item ) );
			if ( '' !== $item ) {
				$sanitized[] = $item;
			}
		}
		return implode( "\n", array_values( array_unique( $sanitized ) ) );
	}

	/**
	 * Convert to 0/1 string.
	 *
	 * @param mixed $value Raw value.
	 * @return string
	 */
	private static function bool_string( $value ): string {
		return rest_sanitize_boolean( $value ) ? '1' : '0';
	}
}
