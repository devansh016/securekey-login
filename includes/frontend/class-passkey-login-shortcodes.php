<?php
/**
 * Frontend shortcodes.
 *
 * @package securekey-login
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class Passkey_Login_Shortcodes {
	/**
	 * Initialize hooks.
	 *
	 * @return void
	 */
	public function init(): void {
		add_shortcode( 'securekey_login_passkey_register', array( $this, 'register_shortcode' ) );
	}

	/**
	 * Render registration button shortcode.
	 *
	 * @return string
	 */
	public function register_shortcode(): string {
		if ( ! is_user_logged_in() ) {
			return '';
		}

		if ( ! Passkey_Login_Settings::passkeys_enabled() || '1' !== (string) Passkey_Login_Settings::get( 'allow_profile_registration' ) ) {
			return '';
		}

		wp_enqueue_script(
			'securekey-login-register',
			PASSKEY_LOGIN_PLUGIN_URL . 'assets/src/js/passkey-register.js',
			array(),
			PASSKEY_LOGIN_VERSION,
			true
		);

		wp_localize_script(
			'securekey-login-register',
			'passkeyLoginRegister',
			array(
				'restUrl' => esc_url_raw( rest_url( 'securekey-login/v1' ) ),
				'nonce'   => wp_create_nonce( 'wp_rest' ),
				'i18n'    => array(
					'notSupported' => __( 'Passkeys are not supported on this browser.', 'securekey-login' ),
					'failed'       => __( 'Passkey registration failed.', 'securekey-login' ),
					'success'      => __( 'Passkey added successfully.', 'securekey-login' ),
					'namePrompt'   => __( 'Enter a name for this passkey:', 'securekey-login' ),
					'nameDefault'  => __( 'My Passkey', 'securekey-login' ),
				),
			)
		);

		return '<button type="button" id="securekey-login-register" class="button button-secondary">' . esc_html__( 'Add Passkey', 'securekey-login' ) . '</button><p id="securekey-login-register-status" style="display:none;"></p>';
	}
}
