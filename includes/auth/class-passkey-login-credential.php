<?php
/**
 * Credential repository.
 *
 * @package passkey-login
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class Passkey_Login_Credential {
	/**
	 * Save credential.
	 *
	 * @param int               $user_id User ID.
	 * @param string            $credential_id_b64 Credential ID.
	 * @param string            $credential_source_json Serialized public key credential source.
	 * @param int               $sign_count Sign count.
	 * @param array<int,string> $transports Transports.
	 * @param string            $name Name.
	 * @return int
	 */
	public function save( int $user_id, string $credential_id_b64, string $credential_source_json, int $sign_count, array $transports = array(), string $name = '' ): int {
		global $wpdb;

		$table         = $this->get_table_name();
		if ( '' === $table ) {
			Passkey_Login_Installer::create_site_tables();
			$table = $this->get_table_name();
			if ( '' === $table ) {
				return 0;
			}
		}
		$credential_id = Passkey_Login_Crypto::base64url_decode( $credential_id_b64 );
		if ( '' === $credential_id ) {
			return 0;
		}

		$inserted = $wpdb->insert(
			$table,
			array(
				'user_id'       => $user_id,
				'credential_id' => $credential_id,
				'public_key'    => $credential_source_json,
				'sign_count'    => max( 0, $sign_count ),
				'transports'    => implode( ',', array_map( 'sanitize_text_field', $transports ) ),
				'name'          => sanitize_text_field( $name ),
				'created_at'    => gmdate( 'Y-m-d H:i:s' ),
			),
			array( '%d', '%s', '%s', '%d', '%s', '%s', '%s' )
		);

		if ( false === $inserted ) {
			Passkey_Login_Installer::create_site_tables();
			$table = $this->get_table_name();
			if ( '' === $table ) {
				return 0;
			}
			$inserted = $wpdb->insert(
				$table,
				array(
					'user_id'       => $user_id,
					'credential_id' => $credential_id,
					'public_key'    => $credential_source_json,
					'sign_count'    => max( 0, $sign_count ),
					'transports'    => implode( ',', array_map( 'sanitize_text_field', $transports ) ),
					'name'          => sanitize_text_field( $name ),
					'created_at'    => gmdate( 'Y-m-d H:i:s' ),
				),
				array( '%d', '%s', '%s', '%d', '%s', '%s', '%s' )
			);
			if ( false === $inserted ) {
				return 0;
			}
		}

		return (int) $wpdb->insert_id;
	}

	/**
	 * Fetch credentials for user.
	 *
	 * @param int $user_id User ID.
	 * @return array<int,array<string,mixed>>
	 */
	public function get_by_user( int $user_id ): array {
		global $wpdb;
		$table = $this->get_table_name();
		if ( '' === $table ) {
			return array();
		}
		$rows  = $wpdb->get_results(
			$wpdb->prepare(
				'SELECT id, credential_id, sign_count, transports, name, created_at, last_used_at FROM %i WHERE user_id = %d ORDER BY id DESC',
				$table,
				$user_id
			),
			ARRAY_A
		);

		if ( ! is_array( $rows ) ) {
			return array();
		}

		foreach ( $rows as &$row ) {
			$row['credential_id'] = Passkey_Login_Crypto::base64url_encode( (string) $row['credential_id'] );
		}

		return $rows;
	}

	/**
	 * Count user credentials.
	 *
	 * @param int $user_id User ID.
	 * @return int
	 */
	public function count_by_user( int $user_id ): int {
		global $wpdb;
		$table = $this->get_table_name();
		if ( '' === $table ) {
			return 0;
		}
		return (int) $wpdb->get_var(
			$wpdb->prepare(
				'SELECT COUNT(*) FROM %i WHERE user_id = %d',
				$table,
				$user_id
			)
		);
	}

	/**
	 * Lookup credential by credential ID.
	 *
	 * @param string $credential_id_b64 Credential ID.
	 * @return array<string,mixed>|null
	 */
	public function get_by_credential_id( string $credential_id_b64 ): ?array {
		global $wpdb;
		$table         = $this->get_table_name();
		$credential_id = Passkey_Login_Crypto::base64url_decode( $credential_id_b64 );

		if ( '' === $credential_id || '' === $table ) {
			return null;
		}

		$row = $wpdb->get_row(
			$wpdb->prepare(
				'SELECT * FROM %i WHERE credential_id = %s LIMIT 1',
				$table,
				$credential_id
			),
			ARRAY_A
		);

		return is_array( $row ) ? $row : null;
	}

	/**
	 * Update source, sign count, and last usage.
	 *
	 * @param int    $credential_pk Credential primary key.
	 * @param int    $new_sign_count New sign count.
	 * @param string $credential_source_json Serialized source JSON.
	 * @return void
	 */
	public function update_after_authentication( int $credential_pk, int $new_sign_count, string $credential_source_json ): void {
		global $wpdb;
		$table = $this->get_table_name();
		if ( '' === $table ) {
			return;
		}

		$wpdb->update(
			$table,
			array(
				'public_key'   => $credential_source_json,
				'sign_count'   => max( 0, $new_sign_count ),
				'last_used_at' => gmdate( 'Y-m-d H:i:s' ),
			),
			array( 'id' => $credential_pk ),
			array( '%s', '%d', '%s' ),
			array( '%d' )
		);
	}

	/**
	 * Deserialize stored public key credential source.
	 *
	 * @param array<string,mixed> $credential Credential row.
	 * @param object              $serializer WebAuthn serializer.
	 * @return mixed|null
	 */
	public function get_public_key_credential_source( array $credential, object $serializer ) {
		if ( empty( $credential['public_key'] ) || ! method_exists( $serializer, 'denormalize' ) ) {
			return null;
		}

		try {
			$data = json_decode( (string) $credential['public_key'], true, 512, JSON_THROW_ON_ERROR );
			return $serializer->denormalize( $data, \Webauthn\PublicKeyCredentialSource::class );
		} catch ( Throwable $exception ) {
			return null;
		}
	}

	/**
	 * Delete credential.
	 *
	 * @param int $credential_pk Credential table ID.
	 * @param int $user_id User ID.
	 * @return bool
	 */
	public function delete( int $credential_pk, int $user_id ): bool {
		global $wpdb;
		$table = $this->get_table_name();
		if ( '' === $table ) {
			return false;
		}

		$deleted = $wpdb->delete(
			$table,
			array(
				'id'      => $credential_pk,
				'user_id' => $user_id,
			),
			array( '%d', '%d' )
		);

		return false !== $deleted;
	}

	/**
	 * Resolve credentials table.
	 *
	 * @return string
	 */
	private function get_table_name(): string {
		global $wpdb;

		$table = $wpdb->prefix . 'passkey_login_credentials';
		$found = $wpdb->get_var(
			$wpdb->prepare( 'SHOW TABLES LIKE %s', $table )
		);

		return is_string( $found ) && '' !== $found ? $table : '';
	}
}
