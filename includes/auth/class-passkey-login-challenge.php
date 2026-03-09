<?php
/**
 * Challenge store.
 *
 * @package passkey-login
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class Passkey_Login_Challenge {
	/**
	 * Challenge TTL in seconds.
	 */
	private const CHALLENGE_TTL = 300;

	/**
	 * Create challenge.
	 *
	 * @param int|null $user_id User ID.
	 * @param string   $type Challenge type.
	 * @return string
	 */
	public function create( ?int $user_id, string $type ): string {
		global $wpdb;

		$challenge = random_bytes( 32 );
		$hash      = Passkey_Login_Crypto::hash_challenge( $challenge );
		$table     = $this->get_table_name();
		if ( '' === $table ) {
			Passkey_Login_Installer::create_site_tables();
			$table = $this->get_table_name();
			if ( '' === $table ) {
				return '';
			}
		}
		$ttl       = self::CHALLENGE_TTL;

		$user_value = null === $user_id ? null : $user_id;

		$inserted = $wpdb->insert(
			$table,
			array(
				'user_id'        => $user_value,
				'challenge_hash' => $hash,
				'type'           => $type,
				'expires_at'     => gmdate( 'Y-m-d H:i:s', time() + $ttl ),
				'created_at'     => gmdate( 'Y-m-d H:i:s' ),
				'ip_address'     => isset( $_SERVER['REMOTE_ADDR'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REMOTE_ADDR'] ) ) : '',
			),
			array( '%d', '%s', '%s', '%s', '%s', '%s' )
		);

		if ( false === $inserted ) {
			Passkey_Login_Installer::create_site_tables();
			$table = $this->get_table_name();
			if ( '' === $table || false === $wpdb->insert(
				$table,
				array(
					'user_id'        => $user_value,
					'challenge_hash' => $hash,
					'type'           => $type,
					'expires_at'     => gmdate( 'Y-m-d H:i:s', time() + $ttl ),
					'created_at'     => gmdate( 'Y-m-d H:i:s' ),
					'ip_address'     => isset( $_SERVER['REMOTE_ADDR'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REMOTE_ADDR'] ) ) : '',
				),
				array( '%d', '%s', '%s', '%s', '%s', '%s' )
			) ) {
				return '';
			}
		}

		return Passkey_Login_Crypto::base64url_encode( $challenge );
	}

	/**
	 * Verify and consume challenge.
	 *
	 * @param string   $challenge_b64 Challenge.
	 * @param string   $type Type.
	 * @param int|null $user_id User ID.
	 * @return bool
	 */
	public function verify_and_consume( string $challenge_b64, string $type, ?int $user_id = null ): bool {
		global $wpdb;

		$challenge_raw = Passkey_Login_Crypto::base64url_decode( $challenge_b64 );
		if ( '' === $challenge_raw ) {
			return false;
		}

		$hash  = Passkey_Login_Crypto::hash_challenge( $challenge_raw );
		$table = $this->get_table_name();
		if ( '' === $table ) {
			return false;
		}

		if ( null !== $user_id ) {
			$row = $wpdb->get_row(
				$wpdb->prepare(
					'SELECT id, expires_at FROM %i WHERE challenge_hash = %s AND type = %s AND user_id = %d ORDER BY id DESC LIMIT 1',
					$table,
					$hash,
					$type,
					$user_id
				)
			);
		} else {
			$row = $wpdb->get_row(
				$wpdb->prepare(
					'SELECT id, expires_at FROM %i WHERE challenge_hash = %s AND type = %s ORDER BY id DESC LIMIT 1',
					$table,
					$hash,
					$type
				)
			);
		}
		if ( ! $row ) {
			return false;
		}

		if ( strtotime( (string) $row->expires_at ) < time() ) {
			$wpdb->delete( $table, array( 'id' => (int) $row->id ), array( '%d' ) );
			return false;
		}

		$wpdb->delete( $table, array( 'id' => (int) $row->id ), array( '%d' ) );

		return true;
	}

	/**
	 * Remove expired challenges.
	 *
	 * @return void
	 */
	public function purge_expired(): void {
		global $wpdb;
		$table = $this->get_table_name();
		if ( '' === $table ) {
			return;
		}

		$wpdb->query(
			$wpdb->prepare(
				'DELETE FROM %i WHERE expires_at < %s',
				$table,
				gmdate( 'Y-m-d H:i:s' )
			)
		);
	}

	/**
	 * Resolve challenge table.
	 *
	 * @return string
	 */
	private function get_table_name(): string {
		global $wpdb;

		$table = $wpdb->prefix . 'passkey_login_challenges';
		$found = $wpdb->get_var(
			$wpdb->prepare( 'SHOW TABLES LIKE %s', $table )
		);

		return is_string( $found ) && '' !== $found ? $table : '';
	}
}
