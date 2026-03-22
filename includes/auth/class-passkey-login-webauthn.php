<?php
/**
 * WebAuthn service.
 *
 * @package securekey-login
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class Passkey_Login_WebAuthn {
	/**
	 * Fixed user verification policy.
	 */
	private const USER_VERIFICATION = 'preferred';

	/**
	 * Max passkeys per user.
	 */
	private const MAX_PASSKEYS_PER_USER = 10;

	/**
	 * Default passkey display name.
	 */
	private const DEFAULT_PASSKEY_NAME = 'My Passkey';

	/**
	 * Challenge store.
	 *
	 * @var Passkey_Login_Challenge
	 */
	private Passkey_Login_Challenge $challenge_store;

	/**
	 * Credential store.
	 *
	 * @var Passkey_Login_Credential
	 */
	private Passkey_Login_Credential $credential_store;

	/**
	 * Constructor.
	 */
	public function __construct() {
		$this->challenge_store  = new Passkey_Login_Challenge();
		$this->credential_store = new Passkey_Login_Credential();
	}

	/**
	 * Begin registration ceremony.
	 *
	 * @param int $user_id User ID.
	 * @return array<string,mixed>|WP_Error
	 */
	public function begin_registration( int $user_id ) {
		if ( $user_id <= 0 ) {
			return new WP_Error( 'securekey_login_invalid_user', __( 'Invalid user.', 'securekey-login' ), array( 'status' => 400 ) );
		}

		$rp        = $this->get_relying_party();
		$user      = get_userdata( $user_id );
		$challenge = $this->challenge_store->create( $user_id, 'register' );
		if ( '' === $challenge ) {
			return new WP_Error( 'securekey_login_challenge_unavailable', __( 'Could not initialize passkey registration.', 'securekey-login' ), array( 'status' => 500 ) );
		}

		if ( ! $user instanceof WP_User ) {
			return new WP_Error( 'securekey_login_invalid_user', __( 'User not found.', 'securekey-login' ), array( 'status' => 404 ) );
		}

		$exclude_credentials = array();
		foreach ( $this->credential_store->get_by_user( $user_id ) as $credential ) {
			$exclude_credentials[] = array(
				'id'   => $credential['credential_id'],
				'type' => 'public-key',
			);
		}

		return array(
			'challenge'              => $challenge,
			'rp'                     => $rp,
			'user'                   => array(
				'id'          => Passkey_Login_Crypto::base64url_encode( (string) $user_id ),
				'name'        => $user->user_login,
				'displayName' => $user->display_name,
			),
			'pubKeyCredParams'       => array(
				array(
					'type' => 'public-key',
					'alg'  => -7,
				),
				array(
					'type' => 'public-key',
					'alg'  => -257,
				),
			),
			'timeout'                => 60000,
			'attestation'            => 'none',
			'excludeCredentials'     => $exclude_credentials,
			'authenticatorSelection' => array(
				'residentKey'      => 'preferred',
				'userVerification' => self::USER_VERIFICATION,
			),
		);
	}

	/**
	 * Complete registration ceremony.
	 *
	 * @param int                 $user_id User ID.
	 * @param array<string,mixed> $response Client payload.
	 * @return array<string,mixed>|WP_Error
	 */
	public function complete_registration( int $user_id, array $response ) {
		$challenge = Passkey_Login_Sanitizer::text( $response['challenge'] ?? '' );
		$origin    = esc_url_raw( wp_unslash( (string) ( $response['origin'] ?? '' ) ) );
		$name      = Passkey_Login_Sanitizer::text( $response['name'] ?? '' );

		if ( '' === $challenge || '' === $origin ) {
			return new WP_Error( 'securekey_login_invalid_payload', __( 'Invalid registration payload.', 'securekey-login' ), array( 'status' => 400 ) );
		}

		if ( ! $this->validate_origin( $origin ) ) {
			return new WP_Error( 'securekey_login_invalid_origin', __( 'Invalid origin.', 'securekey-login' ), array( 'status' => 403 ) );
		}

		$serializer = $this->create_serializer();
		if ( is_wp_error( $serializer ) ) {
			return $serializer;
		}

		$user = get_userdata( $user_id );
		if ( ! $user instanceof WP_User ) {
			return new WP_Error( 'securekey_login_invalid_user', __( 'User not found.', 'securekey-login' ), array( 'status' => 404 ) );
		}

		$public_key_credential = $this->parse_public_key_credential( $response, $serializer );
		if ( is_wp_error( $public_key_credential ) ) {
			return $public_key_credential;
		}

		if ( ! $public_key_credential->response instanceof \Webauthn\AuthenticatorAttestationResponse ) {
			return new WP_Error( 'securekey_login_invalid_payload', __( 'Invalid registration response.', 'securekey-login' ), array( 'status' => 400 ) );
		}

		if ( ! $this->challenge_store->verify_and_consume( $challenge, 'register', $user_id ) ) {
			return new WP_Error( 'securekey_login_invalid_challenge', __( 'Challenge expired or invalid.', 'securekey-login' ), array( 'status' => 400 ) );
		}

		if ( $this->credential_store->count_by_user( $user_id ) >= self::MAX_PASSKEYS_PER_USER ) {
			return new WP_Error( 'securekey_login_limit_reached', __( 'Maximum number of passkeys reached for this account.', 'securekey-login' ), array( 'status' => 400 ) );
		}

		$creation_options = $this->build_creation_options( $user, $challenge );

		try {
			$public_key_credential_source = $this->create_attestation_validator()->check(
				$public_key_credential->response,
				$creation_options,
				$this->get_relying_party_host()
			);
		} catch ( Throwable $exception ) {
			Passkey_Login_Logger::audit(
				'passkey_registration_verification_failed',
				'Passkey registration verification failed.',
				array( 'error' => $exception->getMessage() ),
				'warning',
				$user_id
			);
			return new WP_Error( 'securekey_login_registration_failed', __( 'Passkey verification failed.', 'securekey-login' ), array( 'status' => 400 ) );
		}

		if ( '' === $name ) {
			$name = self::DEFAULT_PASSKEY_NAME;
		}

		$credential_id_b64 = Passkey_Login_Crypto::base64url_encode( $public_key_credential_source->publicKeyCredentialId );
		$serialized_source = $this->serialize_object( $public_key_credential_source, $serializer );
		if ( '' === $serialized_source ) {
			return new WP_Error( 'securekey_login_registration_failed', __( 'Could not save credential.', 'securekey-login' ), array( 'status' => 500 ) );
		}

		$credential_pk = $this->credential_store->save(
			$user_id,
			$credential_id_b64,
			$serialized_source,
			(int) $public_key_credential_source->counter,
			is_array( $public_key_credential_source->transports ) ? array_map( 'sanitize_text_field', $public_key_credential_source->transports ) : array(),
			$name
		);

		if ( 0 === $credential_pk ) {
			return new WP_Error( 'securekey_login_registration_failed', __( 'Could not save credential.', 'securekey-login' ), array( 'status' => 500 ) );
		}

		Passkey_Login_Logger::audit( 'passkey_registered', 'User registered a passkey credential.', array( 'credential_pk' => $credential_pk ) );

		return array(
			'credential_id' => $credential_id_b64,
			'credential_pk' => $credential_pk,
		);
	}

	/**
	 * Begin authentication ceremony.
	 *
	 * @param int|null $user_id User ID.
	 * @return array<string,mixed>|WP_Error
	 */
	public function begin_authentication( ?int $user_id = null ) {
		$challenge = $this->challenge_store->create( $user_id, 'authenticate' );
		if ( '' === $challenge ) {
			return new WP_Error( 'securekey_login_challenge_unavailable', __( 'Could not initialize passkey authentication.', 'securekey-login' ), array( 'status' => 500 ) );
		}
		$allow     = array();

		if ( $user_id ) {
			foreach ( $this->credential_store->get_by_user( $user_id ) as $credential ) {
				$allow[] = array(
					'id'   => $credential['credential_id'],
					'type' => 'public-key',
				);
			}
		}

		return array(
			'challenge'        => $challenge,
			'timeout'          => 60000,
			'rpId'             => $this->get_relying_party()['id'],
			'allowCredentials' => $allow,
			'userVerification' => self::USER_VERIFICATION,
		);
	}

	/**
	 * Complete authentication ceremony.
	 *
	 * @param array<string,mixed> $response Response payload.
	 * @return array<string,mixed>|WP_Error
	 */
	public function complete_authentication( array $response ) {
		$challenge = Passkey_Login_Sanitizer::text( $response['challenge'] ?? '' );
		$origin    = esc_url_raw( wp_unslash( (string) ( $response['origin'] ?? '' ) ) );

		if ( '' === $challenge || '' === $origin ) {
			return new WP_Error( 'securekey_login_invalid_payload', __( 'Invalid authentication payload.', 'securekey-login' ), array( 'status' => 400 ) );
		}

		if ( ! $this->validate_origin( $origin ) ) {
			return new WP_Error( 'securekey_login_invalid_origin', __( 'Invalid origin.', 'securekey-login' ), array( 'status' => 403 ) );
		}

		$serializer = $this->create_serializer();
		if ( is_wp_error( $serializer ) ) {
			return $serializer;
		}

		$public_key_credential = $this->parse_public_key_credential( $response, $serializer );
		if ( is_wp_error( $public_key_credential ) ) {
			return $public_key_credential;
		}

		if ( ! $public_key_credential->response instanceof \Webauthn\AuthenticatorAssertionResponse ) {
			return new WP_Error( 'securekey_login_invalid_payload', __( 'Invalid authentication response.', 'securekey-login' ), array( 'status' => 400 ) );
		}

		$credential_id_b64 = Passkey_Login_Crypto::base64url_encode( $public_key_credential->rawId );
		$credential        = $this->credential_store->get_by_credential_id( $credential_id_b64 );
		if ( ! is_array( $credential ) ) {
			return new WP_Error( 'securekey_login_credential_not_found', __( 'This passkey is invalid. Please use password login and register a new passkey.', 'securekey-login' ), array( 'status' => 404 ) );
		}

		$user_id = isset( $credential['user_id'] ) ? (int) $credential['user_id'] : 0;
		if ( $user_id <= 0 ) {
			return new WP_Error( 'securekey_login_invalid_user', __( 'Credential is not linked to a user.', 'securekey-login' ), array( 'status' => 400 ) );
		}

		// Authentication may start without username, so challenge may be stored without user binding.
		if ( ! $this->challenge_store->verify_and_consume( $challenge, 'authenticate' ) ) {
			return new WP_Error( 'securekey_login_invalid_challenge', __( 'Challenge expired or invalid.', 'securekey-login' ), array( 'status' => 400 ) );
		}

		$public_key_credential_source = $this->credential_store->get_public_key_credential_source( $credential, $serializer );
		if ( ! $public_key_credential_source instanceof \Webauthn\PublicKeyCredentialSource ) {
			return new WP_Error( 'securekey_login_credential_not_found', __( 'This passkey is invalid. Please use password login and register a new passkey.', 'securekey-login' ), array( 'status' => 404 ) );
		}

		$request_options = $this->build_request_options(
			$challenge,
			array(
				array(
					'id'   => $credential_id_b64,
					'type' => 'public-key',
				),
			)
		);

		try {
			$validated_source = $this->create_assertion_validator()->check(
				$public_key_credential_source,
				$public_key_credential->response,
				$request_options,
				$this->get_relying_party_host(),
				$public_key_credential->response->userHandle
			);
		} catch ( Throwable $exception ) {
			Passkey_Login_Logger::audit(
				'passkey_authentication_verification_failed',
				'Passkey authentication verification failed.',
				array(
					'credential_pk' => (int) $credential['id'],
					'error'         => $exception->getMessage(),
				),
				'warning',
				$user_id
			);
			return new WP_Error( 'securekey_login_authentication_failed', __( 'This passkey is invalid. Please use password login and register a new passkey.', 'securekey-login' ), array( 'status' => 403 ) );
		}

		$serialized_source = $this->serialize_object( $validated_source, $serializer );
		if ( '' === $serialized_source ) {
			return new WP_Error( 'securekey_login_authentication_failed', __( 'This passkey is invalid. Please use password login and register a new passkey.', 'securekey-login' ), array( 'status' => 403 ) );
		}

		$this->credential_store->update_after_authentication(
			(int) $credential['id'],
			(int) $validated_source->counter,
			$serialized_source
		);
		Passkey_Login_Logger::audit( 'passkey_authenticated', 'User authenticated with passkey.', array( 'credential_pk' => (int) $credential['id'] ), 'info', $user_id );

		return array(
			'user_id' => $user_id,
		);
	}

	/**
	 * Resolve relying party settings.
	 *
	 * @return array<string,string>
	 */
	private function get_relying_party(): array {
		$network = new Passkey_Login_Network();
		$rp_id   = $network->get_rp_id();

		return array(
			'id'   => $rp_id,
			'name' => wp_specialchars_decode( get_bloginfo( 'name' ), ENT_QUOTES ),
		);
	}

	/**
	 * Validate origin against current network host.
	 *
	 * @param string $origin Origin.
	 * @return bool
	 */
	private function validate_origin( string $origin ): bool {
		$allowed_origins = Passkey_Login_Settings::allowed_origins();
		if ( ! empty( $allowed_origins ) ) {
			return in_array( $origin, $allowed_origins, true );
		}

		$origin_parts = wp_parse_url( $origin );
		if ( ! is_array( $origin_parts ) || empty( $origin_parts['host'] ) ) {
			return false;
		}

		$rp_id = $this->get_relying_party()['id'];
		$host  = (string) $origin_parts['host'];

		$matches_rp = ( $host === $rp_id || str_ends_with( $host, '.' . $rp_id ) );
		if ( ! $matches_rp ) {
			return false;
		}

		$scheme = isset( $origin_parts['scheme'] ) ? strtolower( (string) $origin_parts['scheme'] ) : '';
		if ( 'https' !== $scheme && 'localhost' !== $host ) {
			return false;
		}

		return true;
	}

	/**
	 * Build registration options object for validator.
	 *
	 * @param WP_User $user User.
	 * @param string  $challenge Challenge.
	 * @return Webauthn\PublicKeyCredentialCreationOptions
	 */
	private function build_creation_options( WP_User $user, string $challenge ): \Webauthn\PublicKeyCredentialCreationOptions {
		$rp            = $this->get_relying_party();
		$challenge_raw = Passkey_Login_Crypto::base64url_decode( $challenge );
		$exclude       = array();

		foreach ( $this->credential_store->get_by_user( (int) $user->ID ) as $credential ) {
			$exclude[] = \Webauthn\PublicKeyCredentialDescriptor::create(
				'public-key',
				Passkey_Login_Crypto::base64url_decode( (string) $credential['credential_id'] )
			);
		}

		return \Webauthn\PublicKeyCredentialCreationOptions::create(
			\Webauthn\PublicKeyCredentialRpEntity::create( (string) $rp['name'], (string) $rp['id'] ),
			\Webauthn\PublicKeyCredentialUserEntity::create( $user->user_login, (string) $user->ID, $user->display_name ),
			$challenge_raw,
			array(
				\Webauthn\PublicKeyCredentialParameters::create( 'public-key', -7 ),
				\Webauthn\PublicKeyCredentialParameters::create( 'public-key', -257 ),
			),
			\Webauthn\AuthenticatorSelectionCriteria::create( null, self::USER_VERIFICATION, 'preferred' ),
			'none',
			$exclude,
			60000
		);
	}

	/**
	 * Build assertion request options object for validator.
	 *
	 * @param string                          $challenge Challenge.
	 * @param array<int,array<string,string>> $allow_credentials Allow credentials.
	 * @return Webauthn\PublicKeyCredentialRequestOptions
	 */
	private function build_request_options( string $challenge, array $allow_credentials ): \Webauthn\PublicKeyCredentialRequestOptions {
		$challenge_raw = Passkey_Login_Crypto::base64url_decode( $challenge );
		$allow         = array();

		foreach ( $allow_credentials as $credential ) {
			if ( empty( $credential['id'] ) ) {
				continue;
			}
			$allow[] = \Webauthn\PublicKeyCredentialDescriptor::create(
				'public-key',
				Passkey_Login_Crypto::base64url_decode( (string) $credential['id'] )
			);
		}

		return \Webauthn\PublicKeyCredentialRequestOptions::create(
			$challenge_raw,
			$this->get_relying_party()['id'],
			$allow,
			self::USER_VERIFICATION,
			60000
		);
	}

	/**
	 * Parse WebAuthn public key credential payload.
	 *
	 * @param array<string,mixed> $payload Payload.
	 * @param object              $serializer Serializer.
	 * @return Webauthn\PublicKeyCredential|WP_Error
	 */
	private function parse_public_key_credential( array $payload, object $serializer ) {
		if ( ! method_exists( $serializer, 'denormalize' ) ) {
			return new WP_Error( 'securekey_login_server_error', __( 'Passkey verification service is unavailable.', 'securekey-login' ), array( 'status' => 500 ) );
		}

		try {
			$public_key_credential = $serializer->denormalize( $payload, \Webauthn\PublicKeyCredential::class );
		} catch ( Throwable $exception ) {
			return new WP_Error( 'securekey_login_invalid_payload', __( 'Invalid passkey payload.', 'securekey-login' ), array( 'status' => 400 ) );
		}

		if ( ! $public_key_credential instanceof \Webauthn\PublicKeyCredential ) {
			return new WP_Error( 'securekey_login_invalid_payload', __( 'Invalid passkey payload.', 'securekey-login' ), array( 'status' => 400 ) );
		}

		return $public_key_credential;
	}

	/**
	 * Create serializer.
	 *
	 * @return object|WP_Error
	 */
	private function create_serializer() {
		if ( ! class_exists( '\Webauthn\AuthenticatorAttestationResponseValidator' ) || ! class_exists( '\Webauthn\Denormalizer\WebauthnSerializerFactory' ) ) {
			return new WP_Error( 'securekey_login_server_error', __( 'WebAuthn library is not installed. Run composer install.', 'securekey-login' ), array( 'status' => 500 ) );
		}

		$manager = \Webauthn\AttestationStatement\AttestationStatementSupportManager::create(
			array(
				\Webauthn\AttestationStatement\NoneAttestationStatementSupport::create(),
			)
		);

		return ( new \Webauthn\Denormalizer\WebauthnSerializerFactory( $manager ) )->create();
	}

	/**
	 * Create attestation validator.
	 *
	 * @return Webauthn\AuthenticatorAttestationResponseValidator
	 */
	private function create_attestation_validator(): \Webauthn\AuthenticatorAttestationResponseValidator {
		$factory = $this->create_ceremony_step_manager_factory();
		return \Webauthn\AuthenticatorAttestationResponseValidator::create( $factory->creationCeremony() );
	}

	/**
	 * Create assertion validator.
	 *
	 * @return Webauthn\AuthenticatorAssertionResponseValidator
	 */
	private function create_assertion_validator(): \Webauthn\AuthenticatorAssertionResponseValidator {
		$factory = $this->create_ceremony_step_manager_factory();
		return \Webauthn\AuthenticatorAssertionResponseValidator::create( $factory->requestCeremony() );
	}

	/**
	 * Create ceremony factory with allowed origins.
	 *
	 * @return Webauthn\CeremonyStep\CeremonyStepManagerFactory
	 */
	private function create_ceremony_step_manager_factory(): \Webauthn\CeremonyStep\CeremonyStepManagerFactory {
		$factory = new \Webauthn\CeremonyStep\CeremonyStepManagerFactory();
		$origins = Passkey_Login_Settings::allowed_origins();

		if ( empty( $origins ) ) {
			$origin = $this->get_default_origin();
			if ( '' !== $origin ) {
				$origins = array( $origin );
			}
		}

		if ( ! empty( $origins ) ) {
			$factory->setAllowedOrigins( $origins, true );
		}

		return $factory;
	}

	/**
	 * Serialize WebAuthn object as JSON.
	 *
	 * @param object $value Value.
	 * @param object $serializer Serializer.
	 * @return string
	 */
	private function serialize_object( object $value, object $serializer ): string {
		if ( ! method_exists( $serializer, 'serialize' ) ) {
			return '';
		}

		try {
			$serialized = $serializer->serialize( $value, 'json' );
		} catch ( Throwable $exception ) {
			return '';
		}

		return is_string( $serialized ) ? $serialized : '';
	}

	/**
	 * Resolve RP host for validator.
	 *
	 * @return string
	 */
	private function get_relying_party_host(): string {
		$rp_id = (string) $this->get_relying_party()['id'];
		if ( '' !== $rp_id ) {
			return $rp_id;
		}

		$host = wp_parse_url( home_url( '/' ), PHP_URL_HOST );
		if ( is_string( $host ) && '' !== $host ) {
			return $host;
		}

		return isset( $_SERVER['HTTP_HOST'] ) ? sanitize_text_field( wp_unslash( $_SERVER['HTTP_HOST'] ) ) : '';
	}

	/**
	 * Resolve default origin.
	 *
	 * @return string
	 */
	private function get_default_origin(): string {
		$parts = wp_parse_url( home_url( '/' ) );
		if ( ! is_array( $parts ) || empty( $parts['host'] ) ) {
			return '';
		}

		$scheme = isset( $parts['scheme'] ) ? strtolower( (string) $parts['scheme'] ) : 'https';
		$origin = $scheme . '://' . (string) $parts['host'];

		if ( isset( $parts['port'] ) ) {
			$port             = (int) $parts['port'];
			$is_default_https = ( 'https' === $scheme && 443 === $port );
			$is_default_http  = ( 'http' === $scheme && 80 === $port );
			if ( ! $is_default_https && ! $is_default_http && $port > 0 ) {
				$origin .= ':' . $port;
			}
		}

		return $origin;
	}
}
