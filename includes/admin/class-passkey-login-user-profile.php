<?php
/**
 * User profile UI.
 *
 * @package securekey-login
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class Passkey_Login_User_Profile {
	/**
	 * Initialize hooks.
	 *
	 * @return void
	 */
	public function init(): void {
		add_action( 'show_user_profile', array( $this, 'render' ) );
		add_action( 'edit_user_profile', array( $this, 'render' ) );
	}

	/**
	 * Render passkeys block.
	 *
	 * @param WP_User $user User.
	 * @return void
	 */
	public function render( WP_User $user ): void {
		if ( ! current_user_can( 'edit_user', $user->ID ) ) {
			return;
		}

		$store        = new Passkey_Login_Credential();
		$credentials  = $store->get_by_user( (int) $user->ID );
		$can_register = Passkey_Login_Settings::passkeys_enabled() && '1' === (string) Passkey_Login_Settings::get( 'allow_profile_registration' );
		?>
		<h2><?php echo esc_html__( 'Passkey Devices', 'securekey-login' ); ?></h2>
		<table class="widefat striped">
			<thead>
				<tr>
					<th><?php echo esc_html__( 'Name', 'securekey-login' ); ?></th>
					<th><?php echo esc_html__( 'Created', 'securekey-login' ); ?></th>
					<th><?php echo esc_html__( 'Last Used', 'securekey-login' ); ?></th>
					<th><?php echo esc_html__( 'Actions', 'securekey-login' ); ?></th>
				</tr>
			</thead>
			<tbody>
				<?php if ( empty( $credentials ) ) : ?>
					<tr><td colspan="4"><?php echo esc_html__( 'No passkeys registered.', 'securekey-login' ); ?></td></tr>
				<?php else : ?>
					<?php foreach ( $credentials as $credential ) : ?>
						<tr>
							<td>
								<?php
								$name = (string) $credential['name'];
								if ( '' === $name ) {
									$name = __( 'Passkey', 'securekey-login' );
								}
								echo esc_html( $name );
								?>
							</td>
							<td><?php echo esc_html( (string) $credential['created_at'] ); ?></td>
							<td>
								<?php
								$last_used_at = (string) $credential['last_used_at'];
								if ( '' === $last_used_at ) {
									$last_used_at = '-';
								}
								echo esc_html( $last_used_at );
								?>
							</td>
							<td>
								<button type="button" class="button securekey-login-delete-passkey" data-credential-id="<?php echo esc_attr( (string) $credential['id'] ); ?>"><?php echo esc_html__( 'Delete', 'securekey-login' ); ?></button>
							</td>
						</tr>
					<?php endforeach; ?>
				<?php endif; ?>
			</tbody>
		</table>
		<?php if ( $can_register ) : ?>
			<p>
				<button type="button" id="securekey-login-register" class="button button-secondary"><?php echo esc_html__( 'Add Passkey', 'securekey-login' ); ?></button>
			</p>
		<?php endif; ?>
		<p id="securekey-login-register-status" style="display:none;"></p>
		<?php

		if ( $can_register ) {
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
						'failed'       => __( 'Passkey operation failed.', 'securekey-login' ),
						'success'      => __( 'Passkey updated.', 'securekey-login' ),
						'namePrompt'   => __( 'Enter a name for this passkey:', 'securekey-login' ),
						'nameDefault'  => __( 'My Passkey', 'securekey-login' ),
					),
				)
			);
		}
	}
}
