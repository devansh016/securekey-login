<?php
/**
 * Login form integration.
 *
 * @package securekey-login
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class Passkey_Login_Login_Form {
	/**
	 * Setup hooks.
	 *
	 * @return void
	 */
	public function init(): void {
		add_action( 'login_form', array( $this, 'render_login_button' ) );
		add_action( 'login_enqueue_scripts', array( $this, 'enqueue_assets' ) );
	}

	/**
	 * Render passkey login button.
	 *
	 * @return void
	 */
	public function render_login_button(): void {
		if ( ! Passkey_Login_Settings::passkeys_enabled() || '1' !== (string) Passkey_Login_Settings::get( 'show_login_button' ) ) {
			return;
		}

		echo '<div class="securekey-login-login-wrap">';
		echo '<div class="securekey-login-divider" aria-hidden="true"><span>' . esc_html__( 'or', 'securekey-login' ) . '</span></div>';
		echo '<p class="securekey-login-button-wrap">';
		echo '<button type="button" id="securekey-login-login" class="button button-secondary button-large">';
		echo '<span class="securekey-login-label">' . esc_html__( 'Sign in with a passkey', 'securekey-login' ) . '</span>';
		echo '</button>';
		echo '</p>';
		echo '</div>';
		echo '<input type="hidden" name="securekey_login_passkey_assertion" id="securekey-login-assertion" value="" />';
		echo '<input type="hidden" name="securekey_login_passkey_nonce" value="' . esc_attr( wp_create_nonce( 'securekey_login_passkey_login' ) ) . '" />';
		echo '<p id="securekey-login-status" class="message" style="display:none;"></p>';
	}

	/**
	 * Enqueue login assets.
	 *
	 * @return void
	 */
	public function enqueue_assets(): void {
		if ( ! Passkey_Login_Settings::passkeys_enabled() || '1' !== (string) Passkey_Login_Settings::get( 'show_login_button' ) ) {
			return;
		}

		wp_enqueue_style(
			'securekey-login-login',
			PASSKEY_LOGIN_PLUGIN_URL . 'assets/src/css/login.css',
			array(),
			PASSKEY_LOGIN_VERSION
		);

		wp_enqueue_script(
			'securekey-login-authenticate',
			PASSKEY_LOGIN_PLUGIN_URL . 'assets/src/js/passkey-authenticate.js',
			array(),
			PASSKEY_LOGIN_VERSION,
			true
		);

		wp_localize_script(
			'securekey-login-authenticate',
			'passkeyLoginAuth',
			array(
				'restUrl' => esc_url_raw( rest_url( 'securekey-login/v1' ) ),
				'nonce'   => wp_create_nonce( 'wp_rest' ),
				'i18n'    => array(
					'notSupported' => __( 'Passkeys are not supported on this browser.', 'securekey-login' ),
					'failed'       => __( 'Passkey authentication failed.', 'securekey-login' ),
				),
			)
		);
	}
}
