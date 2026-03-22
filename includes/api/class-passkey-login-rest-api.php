<?php
/**
 * REST API controller.
 *
 * @package securekey-login
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class Passkey_Login_REST_API {
	/**
	 * Namespace.
	 */
	private const NAMESPACE = 'securekey-login/v1';

	/**
	 * Rate-limit max attempts per window.
	 */
	private const RATE_LIMIT_ATTEMPTS = 20;

	/**
	 * Rate-limit window (seconds).
	 */
	private const RATE_LIMIT_WINDOW = 300;

	/**
	 * Initialize hooks.
	 *
	 * @return void
	 */
	public function init(): void {
		add_action( 'rest_api_init', array( $this, 'register_routes' ) );
	}

	/**
	 * Register routes.
	 *
	 * @return void
	 */
	public function register_routes(): void {
		register_rest_route(
			self::NAMESPACE,
			'/register/begin',
			array(
				'methods'             => WP_REST_Server::CREATABLE,
				'callback'            => array( $this, 'register_begin' ),
				'permission_callback' => '__return_true',
			)
		);

		register_rest_route(
			self::NAMESPACE,
			'/register/complete',
			array(
				'methods'             => WP_REST_Server::CREATABLE,
				'callback'            => array( $this, 'register_complete' ),
				'permission_callback' => '__return_true',
			)
		);

		register_rest_route(
			self::NAMESPACE,
			'/authenticate/begin',
			array(
				'methods'             => WP_REST_Server::CREATABLE,
				'callback'            => array( $this, 'authenticate_begin' ),
				'permission_callback' => '__return_true',
			)
		);

		register_rest_route(
			self::NAMESPACE,
			'/authenticate/complete',
			array(
				'methods'             => WP_REST_Server::CREATABLE,
				'callback'            => array( $this, 'authenticate_complete' ),
				'permission_callback' => '__return_true',
			)
		);

		register_rest_route(
			self::NAMESPACE,
			'/credentials',
			array(
				'methods'             => WP_REST_Server::READABLE,
				'callback'            => array( $this, 'credentials' ),
				'permission_callback' => '__return_true',
			)
		);

		register_rest_route(
			self::NAMESPACE,
			'/credentials/(?P<id>\d+)',
			array(
				'methods'             => WP_REST_Server::DELETABLE,
				'callback'            => array( $this, 'delete_credential' ),
				'permission_callback' => '__return_true',
			)
		);
	}

	/**
	 * Begin registration endpoint.
	 *
	 * @param WP_REST_Request $request Request.
	 * @return WP_REST_Response|WP_Error
	 */
	public function register_begin( WP_REST_Request $request ) {
		if ( ! $this->verify_rest_nonce( $request ) ) {
			return $this->error( 'securekey_login_invalid_nonce', __( 'REST nonce verification failed.', 'securekey-login' ), 403 );
		}

		$user_id = get_current_user_id();
		if ( $user_id <= 0 ) {
			return $this->error( 'securekey_login_not_authenticated', __( 'You must be logged in.', 'securekey-login' ), 401 );
		}

		if ( ! $this->check_rate_limit( 'register_begin', $request ) ) {
			return $this->error( 'securekey_login_rate_limited', __( 'Too many attempts. Please wait and retry.', 'securekey-login' ), 429 );
		}

		$webauthn = new Passkey_Login_WebAuthn();
		$result   = $webauthn->begin_registration( $user_id );
		if ( is_wp_error( $result ) ) {
			return $result;
		}

		return rest_ensure_response(
			array(
				'success' => true,
				'data'    => $result,
			)
		);
	}

	/**
	 * Complete registration endpoint.
	 *
	 * @param WP_REST_Request $request Request.
	 * @return WP_REST_Response|WP_Error
	 */
	public function register_complete( WP_REST_Request $request ) {
		if ( ! $this->verify_rest_nonce( $request ) ) {
			return $this->error( 'securekey_login_invalid_nonce', __( 'REST nonce verification failed.', 'securekey-login' ), 403 );
		}

		$user_id = get_current_user_id();
		if ( $user_id <= 0 ) {
			return $this->error( 'securekey_login_not_authenticated', __( 'You must be logged in.', 'securekey-login' ), 401 );
		}

		if ( ! $this->check_rate_limit( 'register_complete', $request ) ) {
			return $this->error( 'securekey_login_rate_limited', __( 'Too many attempts. Please wait and retry.', 'securekey-login' ), 429 );
		}

		$payload  = Passkey_Login_Sanitizer::json_object( $request->get_param( 'credential' ) );
		$webauthn = new Passkey_Login_WebAuthn();
		$result   = $webauthn->complete_registration( $user_id, $payload );

		if ( is_wp_error( $result ) ) {
			return $result;
		}

		return rest_ensure_response(
			array(
				'success' => true,
				'data'    => $result,
			)
		);
	}

	/**
	 * Begin authentication endpoint.
	 *
	 * @param WP_REST_Request $request Request.
	 * @return WP_REST_Response|WP_Error
	 */
	public function authenticate_begin( WP_REST_Request $request ) {
		if ( ! $this->verify_rest_nonce( $request ) ) {
			return $this->error( 'securekey_login_invalid_nonce', __( 'REST nonce verification failed.', 'securekey-login' ), 403 );
		}

		if ( ! $this->check_rate_limit( 'authenticate_begin', $request ) ) {
			return $this->error( 'securekey_login_rate_limited', __( 'Too many attempts. Please wait and retry.', 'securekey-login' ), 429 );
		}

		$username = Passkey_Login_Sanitizer::text( $request->get_param( 'username' ) );
		$user_id  = null;
		if ( '' !== $username ) {
			$user = get_user_by( 'login', $username );
			if ( $user instanceof WP_User ) {
				$user_id = (int) $user->ID;
			}
		}

		$webauthn = new Passkey_Login_WebAuthn();
		$result   = $webauthn->begin_authentication( $user_id );
		if ( is_wp_error( $result ) ) {
			return $result;
		}

		return rest_ensure_response(
			array(
				'success' => true,
				'data'    => $result,
			)
		);
	}

	/**
	 * Complete authentication endpoint.
	 *
	 * @param WP_REST_Request $request Request.
	 * @return WP_REST_Response|WP_Error
	 */
	public function authenticate_complete( WP_REST_Request $request ) {
		if ( ! $this->verify_rest_nonce( $request ) ) {
			return $this->error( 'securekey_login_invalid_nonce', __( 'REST nonce verification failed.', 'securekey-login' ), 403 );
		}

		if ( ! $this->check_rate_limit( 'authenticate_complete', $request ) ) {
			return $this->error( 'securekey_login_rate_limited', __( 'Too many attempts. Please wait and retry.', 'securekey-login' ), 429 );
		}

		$payload  = Passkey_Login_Sanitizer::json_object( $request->get_param( 'assertion' ) );
		$webauthn = new Passkey_Login_WebAuthn();
		$result   = $webauthn->complete_authentication( $payload );

		if ( is_wp_error( $result ) ) {
			return $result;
		}

		$user_id = (int) $result['user_id'];
		$user    = get_user_by( 'id', $user_id );
		if ( ! $user instanceof WP_User ) {
			return $this->error( 'securekey_login_user_not_found', __( 'Authenticated user was not found.', 'securekey-login' ), 404 );
		}

		wp_set_current_user( $user_id );
		wp_set_auth_cookie( $user_id, false, is_ssl() );

		return rest_ensure_response(
			array(
				'success' => true,
				'data'    => array(
					'user_id'  => $user_id,
					'redirect' => admin_url(),
				),
			)
		);
	}

	/**
	 * List current user credentials.
	 *
	 * @param WP_REST_Request $request Request.
	 * @return WP_REST_Response|WP_Error
	 */
	public function credentials( WP_REST_Request $request ) {
		if ( ! $this->verify_rest_nonce( $request ) ) {
			return $this->error( 'securekey_login_invalid_nonce', __( 'REST nonce verification failed.', 'securekey-login' ), 403 );
		}

		$user_id = get_current_user_id();
		if ( $user_id <= 0 ) {
			return $this->error( 'securekey_login_not_authenticated', __( 'You must be logged in.', 'securekey-login' ), 401 );
		}

		$store = new Passkey_Login_Credential();

		return rest_ensure_response(
			array(
				'success' => true,
				'data'    => $store->get_by_user( $user_id ),
			)
		);
	}

	/**
	 * Delete credential.
	 *
	 * @param WP_REST_Request $request Request.
	 * @return WP_REST_Response|WP_Error
	 */
	public function delete_credential( WP_REST_Request $request ) {
		if ( ! $this->verify_rest_nonce( $request ) ) {
			return $this->error( 'securekey_login_invalid_nonce', __( 'REST nonce verification failed.', 'securekey-login' ), 403 );
		}

		$user_id = get_current_user_id();
		if ( $user_id <= 0 ) {
			return $this->error( 'securekey_login_not_authenticated', __( 'You must be logged in.', 'securekey-login' ), 401 );
		}

		$credential_id = Passkey_Login_Sanitizer::absint( $request->get_param( 'id' ) );
		if ( $credential_id <= 0 ) {
			return $this->error( 'securekey_login_invalid_id', __( 'Invalid credential ID.', 'securekey-login' ), 400 );
		}

		$store   = new Passkey_Login_Credential();
		$deleted = $store->delete( $credential_id, $user_id );
		if ( ! $deleted ) {
			return $this->error( 'securekey_login_delete_failed', __( 'Could not delete credential.', 'securekey-login' ), 404 );
		}

		Passkey_Login_Logger::audit( 'passkey_deleted', 'User deleted a passkey credential.', array( 'credential_pk' => $credential_id ) );

		return rest_ensure_response(
			array(
				'success' => true,
				'data'    => array(
					'deleted' => true,
				),
			)
		);
	}

	/**
	 * Verify REST nonce.
	 *
	 * @param WP_REST_Request $request Request.
	 * @return bool
	 */
	private function verify_rest_nonce( WP_REST_Request $request ): bool {
		$nonce = $request->get_header( 'X-WP-Nonce' );
		if ( empty( $nonce ) ) {
			$nonce = $request->get_param( '_wpnonce' );
		}

		return is_string( $nonce ) && wp_verify_nonce( $nonce, 'wp_rest' );
	}

	/**
	 * Very small IP+action rate limit.
	 *
	 * @param string          $action Action key.
	 * @param WP_REST_Request $request Request.
	 * @return bool
	 */
	private function check_rate_limit( string $action, WP_REST_Request $request ): bool {
		$ip      = $request->get_header( 'X-Forwarded-For' );
		$remote  = filter_input( INPUT_SERVER, 'REMOTE_ADDR', FILTER_SANITIZE_FULL_SPECIAL_CHARS );
		$remote  = is_string( $remote ) && '' !== $remote ? $remote : 'unknown';
		$ip      = is_string( $ip ) && '' !== $ip ? explode( ',', $ip )[0] : $remote;
		$ip      = sanitize_text_field( trim( (string) $ip ) );
		$key     = 'securekey_login_rl_' . md5( $action . '|' . $ip );
		$attempt = (int) get_transient( $key );

		if ( $attempt >= self::RATE_LIMIT_ATTEMPTS ) {
			return false;
		}

		set_transient( $key, $attempt + 1, self::RATE_LIMIT_WINDOW );
		return true;
	}

	/**
	 * Build structured REST error.
	 *
	 * @param string $code Code.
	 * @param string $message Message.
	 * @param int    $status HTTP status.
	 * @return WP_Error
	 */
	private function error( string $code, string $message, int $status ): WP_Error {
		return new WP_Error(
			$code,
			$message,
			array(
				'status' => $status,
				'error'  => array(
					'code'    => $code,
					'message' => $message,
				),
			)
		);
	}
}
