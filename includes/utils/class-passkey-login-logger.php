<?php
/**
 * Logger.
 *
 * @package passkey-login
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class Passkey_Login_Logger {
	/**
	 * Write an audit event.
	 *
	 * @param string               $event Event name.
	 * @param string               $message Message.
	 * @param array<string, mixed> $meta Metadata.
	 * @param string               $severity Severity.
	 * @param int|null             $user_id User ID.
	 * @return void
	 */
	public static function audit( string $event, string $message, array $meta = array(), string $severity = 'info', ?int $user_id = null ): void {
		global $wpdb;

		$meta_sanitized = self::sanitize_meta( $meta );
		$site_id        = get_current_blog_id();
		if ( null === $user_id ) {
			$user_id = get_current_user_id();
		}

		$main_prefix = is_multisite() ? $wpdb->get_blog_prefix( get_main_site_id() ) : $wpdb->prefix;
		$table       = $main_prefix . 'passkey_login_network_audit_log';

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery -- plugin audit events are persisted to a dedicated custom table.
		$wpdb->insert(
			$table,
			array(
				'site_id'    => $site_id,
				'user_id'    => $user_id > 0 ? $user_id : null,
				'event'      => $event,
				'severity'   => $severity,
				'message'    => $message,
				'meta'       => wp_json_encode( $meta_sanitized ),
				'created_at' => gmdate( 'Y-m-d H:i:s' ),
			),
			array( '%d', '%d', '%s', '%s', '%s', '%s', '%s' )
		);
	}

	/**
	 * Remove sensitive keys.
	 *
	 * @param array<string,mixed> $meta Metadata.
	 * @return array<string,mixed>
	 */
	private static function sanitize_meta( array $meta ): array {
		$blocked = array(
			'private_key',
			'attestation_object',
			'client_data_json',
			'authenticator_data',
			'signature',
		);

		foreach ( $blocked as $key ) {
			if ( isset( $meta[ $key ] ) ) {
				unset( $meta[ $key ] );
			}
		}

		return $meta;
	}
}
