<?php
/**
 * Site admin settings.
 *
 * @package securekey-login
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class Passkey_Login_Admin {
	/**
	 * Initialize hooks.
	 *
	 * @return void
	 */
	public function init(): void {
		add_action( 'admin_menu', array( $this, 'admin_menu' ) );
		add_action( 'admin_init', array( $this, 'register_settings' ) );
	}

	/**
	 * Add admin page.
	 *
	 * @return void
	 */
	public function admin_menu(): void {
		add_options_page(
			__( 'Securekey Login', 'securekey-login' ),
			__( 'Passkeys', 'securekey-login' ),
			'manage_options',
			'securekey-login-settings',
			array( $this, 'render_settings_page' )
		);
	}

	/**
	 * Register site settings.
	 *
	 * @return void
	 */
	public function register_settings(): void {
		register_setting(
			'securekey_login_settings',
			'securekey_login_settings',
			array(
				'type'              => 'array',
				'sanitize_callback' => array( 'Passkey_Login_Settings', 'sanitize_site_settings' ),
				'default'           => Passkey_Login_Settings::site_defaults(),
			)
		);

		add_settings_section( 'securekey_login_site', __( 'Site Settings', 'securekey-login' ), '__return_false', 'securekey_login_settings' );
		$this->add_checkbox( 'enable_passkeys', __( 'Enable passkeys', 'securekey-login' ), 'securekey_login_site' );
		$this->add_checkbox( 'show_login_button', __( 'Show passkey button on wp-login.php', 'securekey-login' ), 'securekey_login_site' );
		$this->add_checkbox( 'allow_profile_registration', __( 'Allow passkey registration from profile', 'securekey-login' ), 'securekey_login_site' );
	}

	/**
	 * Render checkbox field.
	 *
	 * @param array<string,mixed> $args Field args.
	 * @return void
	 */
	public function render_checkbox( array $args ): void {
		$settings = Passkey_Login_Settings::site_settings();
		$key      = (string) $args['key'];
		$value    = isset( $settings[ $key ] ) ? (string) $settings[ $key ] : '0';

		echo '<label><input type="checkbox" name="securekey_login_settings[' . esc_attr( $key ) . ']" value="1" ' . checked( '1', $value, false ) . disabled( true, $this->is_site_locked(), false ) . ' /> ' . esc_html( (string) $args['label'] ) . '</label>';
	}


	/**
	 * Render settings page.
	 *
	 * @return void
	 */
	public function render_settings_page(): void {
		if ( ! current_user_can( 'manage_options' ) ) {
			return;
		}
		?>
		<div class="wrap">
			<h1><?php echo esc_html__( 'Securekey Login Settings', 'securekey-login' ); ?></h1>
			<?php if ( $this->is_site_locked() ) : ?>
				<div class="notice notice-info"><p><?php echo esc_html__( 'Site-level overrides are disabled by network policy. Settings are read-only.', 'securekey-login' ); ?></p></div>
			<?php endif; ?>
			<form method="post" action="options.php">
				<?php
				settings_fields( 'securekey_login_settings' );
				do_settings_sections( 'securekey_login_settings' );
				submit_button();
				?>
			</form>
		</div>
		<?php
	}

	/**
	 * Register a checkbox field.
	 *
	 * @param string $key Key.
	 * @param string $label Label.
	 * @param string $section Section.
	 * @return void
	 */
	private function add_checkbox( string $key, string $label, string $section ): void {
		add_settings_field(
			$key,
			$label,
			array( $this, 'render_checkbox' ),
			'securekey_login_settings',
			$section,
			array(
				'key'   => $key,
				'label' => $label,
			)
		);
	}

	/**
	 * Whether site settings are locked by network policy.
	 *
	 * @return bool
	 */
	private function is_site_locked(): bool {
		return is_multisite() && ! Passkey_Login_Settings::allow_site_overrides();
	}
}
