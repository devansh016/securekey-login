<?php
/**
 * WordPress authentication hook integration.
 *
 * @package securekey-login
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class Passkey_Login_Authenticator {
	/**
	 * Init hooks.
	 *
	 * @return void
	 */
	public function init(): void {
		add_filter( 'authenticate', array( $this, 'authenticate' ), 30, 3 );
	}

	/**
	 * Authenticate using passkey assertion when present.
	 *
	 * @param WP_User|WP_Error|null $user Existing auth result.
	 * @param string                $username Username.
	 * @param string                $password Password.
	 * @return WP_User|WP_Error|null
	 */
	public function authenticate( $user, string $username, string $password ) {
		if ( ! Passkey_Login_Settings::passkeys_enabled() ) {
			return $user;
		}

		if ( $user instanceof WP_User ) {
			return $user;
		}

		if ( empty( $_POST['securekey_login_passkey_assertion'] ) ) {
			return $user;
		}

		if ( ! isset( $_POST['securekey_login_passkey_nonce'] ) || ! wp_verify_nonce( sanitize_text_field( wp_unslash( $_POST['securekey_login_passkey_nonce'] ) ), 'securekey_login_passkey_login' ) ) {
			return new WP_Error( 'securekey_login_invalid_nonce', __( 'Security check failed.', 'securekey-login' ) );
		}

		$assertion_raw = sanitize_text_field( wp_unslash( $_POST['securekey_login_passkey_assertion'] ) );
		if ( ! is_string( $assertion_raw ) || '' === trim( $assertion_raw ) ) {
			return new WP_Error( 'securekey_login_invalid_payload', __( 'Invalid passkey payload.', 'securekey-login' ) );
		}
		$assertion = Passkey_Login_Sanitizer::json_object(
			$assertion_raw,
			array( 'id', 'type', 'rawId', 'response' )
		);

		if ( ! isset( $assertion['response'] ) || ! is_array( $assertion['response'] ) ) {
			return new WP_Error( 'securekey_login_invalid_payload', __( 'Invalid passkey payload.', 'securekey-login' ) );
		}

		foreach ( array( 'clientDataJSON', 'authenticatorData', 'signature' ) as $required_key ) {
			if ( ! isset( $assertion['response'][ $required_key ] ) || ! is_string( $assertion['response'][ $required_key ] ) || '' === $assertion['response'][ $required_key ] ) {
				return new WP_Error( 'securekey_login_invalid_payload', __( 'Invalid passkey payload.', 'securekey-login' ) );
			}
		}

		$webauthn  = new Passkey_Login_WebAuthn();
		$result    = $webauthn->complete_authentication( $assertion );

		if ( is_wp_error( $result ) ) {
			// User explicitly attempted passkey auth; surface the passkey error.
			return $result;
		}

		$auth_user = get_user_by( 'id', (int) $result['user_id'] );
		if ( ! $auth_user instanceof WP_User ) {
			return new WP_Error( 'securekey_login_user_not_found', __( 'Could not load authenticated user.', 'securekey-login' ) );
		}

		return $auth_user;
	}
}
