<?php
/**
 * Crypto helpers.
 *
 * @package securekey-login
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class Passkey_Login_Crypto {
	/**
	 * URL-safe base64 encode.
	 *
	 * @param string $binary Data.
	 * @return string
	 */
	public static function base64url_encode( string $binary ): string {
		return rtrim( strtr( base64_encode( $binary ), '+/', '-_' ), '=' );
	}

	/**
	 * URL-safe base64 decode.
	 *
	 * @param string $value Encoded value.
	 * @return string
	 */
	public static function base64url_decode( string $value ): string {
		$padding = strlen( $value ) % 4;
		if ( 0 !== $padding ) {
			$value .= str_repeat( '=', 4 - $padding );
		}

		$decoded = base64_decode( strtr( $value, '-_', '+/' ), true );
		if ( false === $decoded ) {
			return '';
		}

		return $decoded;
	}

	/**
	 * Constant-time hash for challenge storage.
	 *
	 * @param string $value Raw challenge.
	 * @return string
	 */
	public static function hash_challenge( string $value ): string {
		return hash( 'sha256', $value );
	}
}
