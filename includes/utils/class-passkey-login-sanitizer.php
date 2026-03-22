<?php
/**
 * Sanitizer helpers.
 *
 * @package securekey-login
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class Passkey_Login_Sanitizer {
	/**
	 * Sanitize text field.
	 *
	 * @param mixed $value Raw value.
	 * @return string
	 */
	public static function text( $value ): string {
		return sanitize_text_field( wp_unslash( (string) $value ) );
	}

	/**
	 * Sanitize key.
	 *
	 * @param mixed $value Raw key.
	 * @return string
	 */
	public static function key( $value ): string {
		return sanitize_key( wp_unslash( (string) $value ) );
	}

	/**
	 * Sanitize integer.
	 *
	 * @param mixed $value Raw number.
	 * @return int
	 */
	public static function absint( $value ): int {
		return absint( $value );
	}

	/**
	 * Sanitize boolean flag.
	 *
	 * @param mixed $value Raw bool.
	 * @return bool
	 */
	public static function bool( $value ): bool {
		return (bool) rest_sanitize_boolean( $value );
	}

	/**
	 * Decode JSON object safely.
	 *
	 * @param mixed             $value Raw JSON.
	 * @param array<int,string> $required_keys Required top-level keys.
	 * @return array<string,mixed>
	 */
	public static function json_object( $value, array $required_keys = array() ): array {
		if ( is_array( $value ) ) {
			return self::validate_json_object( $value, $required_keys );
		}

		try {
			$decoded = json_decode( (string) $value, true, 512, JSON_THROW_ON_ERROR );
		} catch ( JsonException $exception ) {
			return array();
		}

		if ( ! is_array( $decoded ) ) {
			return array();
		}

		return self::validate_json_object( $decoded, $required_keys );
	}

	/**
	 * Validate a decoded JSON object.
	 *
	 * @param array<string,mixed> $value Decoded object.
	 * @param array<int,string>   $required_keys Required keys.
	 * @return array<string,mixed>
	 */
	private static function validate_json_object( array $value, array $required_keys ): array {
		foreach ( $required_keys as $required_key ) {
			if ( ! is_string( $required_key ) || '' === $required_key || ! array_key_exists( $required_key, $value ) ) {
				return array();
			}
		}

		return $value;
	}
}
