<?php
/**
 * Network admin settings and audit UI.
 *
 * @package securekey-login
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class Passkey_Login_Network_Admin {
	/**
	 * Initialize hooks.
	 *
	 * @return void
	 */
	public function init(): void {
		if ( ! is_multisite() ) {
			return;
		}

		add_action( 'network_admin_menu', array( $this, 'menu' ) );
		add_action( 'network_admin_edit_securekey_login_network_settings', array( $this, 'save_settings' ) );
	}

	/**
	 * Register menu.
	 *
	 * @return void
	 */
	public function menu(): void {
		add_menu_page(
			__( 'Securekey Login', 'securekey-login' ),
			__( 'Passkeys', 'securekey-login' ),
			'manage_network_options',
			'securekey-login-network',
			array( $this, 'render' ),
			'dashicons-shield',
			58
		);
	}

	/**
	 * Save network settings.
	 *
	 * @return void
	 */
	public function save_settings(): void {
		if ( ! current_user_can( 'manage_network_options' ) ) {
			wp_die( esc_html__( 'Permission denied.', 'securekey-login' ) );
		}

		check_admin_referer( 'securekey_login_network_settings' );
		$raw_input = filter_input( INPUT_POST, 'securekey_login_network_settings', FILTER_SANITIZE_FULL_SPECIAL_CHARS, FILTER_REQUIRE_ARRAY );
		$input     = is_array( $raw_input ) ? $raw_input : array();
		$input     = wp_unslash( $input );
		$input     = array_intersect_key( $input, self::allowed_settings_keys() );
		$clean = Passkey_Login_Settings::sanitize_network_settings( $input );
		update_site_option( 'securekey_login_network_settings', $clean );

		wp_safe_redirect( network_admin_url( 'admin.php?page=securekey-login-network&tab=settings&updated=1' ) );
		exit;
	}

	/**
	 * Render screen.
	 *
	 * @return void
	 */
	public function render(): void {
		if ( ! current_user_can( 'manage_network_options' ) ) {
			return;
		}

		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- read-only tab switch for admin screen rendering.
		$tab = isset( $_GET['tab'] ) ? sanitize_key( wp_unslash( $_GET['tab'] ) ) : 'settings';
		?>
		<div class="wrap">
			<h1><?php echo esc_html__( 'Securekey Login', 'securekey-login' ); ?></h1>
			<nav class="nav-tab-wrapper">
				<a href="<?php echo esc_url( network_admin_url( 'admin.php?page=securekey-login-network&tab=settings' ) ); ?>" class="nav-tab <?php echo 'settings' === $tab ? 'nav-tab-active' : ''; ?>"><?php echo esc_html__( 'Settings', 'securekey-login' ); ?></a>
				<a href="<?php echo esc_url( network_admin_url( 'admin.php?page=securekey-login-network&tab=audit' ) ); ?>" class="nav-tab <?php echo 'audit' === $tab ? 'nav-tab-active' : ''; ?>"><?php echo esc_html__( 'Audit Log', 'securekey-login' ); ?></a>
				<a href="<?php echo esc_url( network_admin_url( 'admin.php?page=securekey-login-network&tab=sites' ) ); ?>" class="nav-tab <?php echo 'sites' === $tab ? 'nav-tab-active' : ''; ?>"><?php echo esc_html__( 'Site Overview', 'securekey-login' ); ?></a>
			</nav>
			<?php
			switch ( $tab ) {
				case 'audit':
					$this->render_audit_tab();
					break;
				case 'sites':
					$this->render_sites_tab();
					break;
				case 'settings':
				default:
					$this->render_settings_tab();
			}
			?>
		</div>
		<?php
	}

	/**
	 * Render settings tab.
	 *
	 * @return void
	 */
	private function render_settings_tab(): void {
		global $wp_roles;
		$settings = Passkey_Login_Settings::network_settings();
		?>
		<form method="post" action="<?php echo esc_url( network_admin_url( 'edit.php?action=securekey_login_network_settings' ) ); ?>">
			<?php wp_nonce_field( 'securekey_login_network_settings' ); ?>
			<h2><?php echo esc_html__( 'Network Settings', 'securekey-login' ); ?></h2>
			<table class="form-table" role="presentation">
				<tr>
					<th scope="row"><label for="securekey-login-network-enable-passkeys"><?php echo esc_html__( 'Enable passkeys', 'securekey-login' ); ?></label></th>
					<td><label><input type="checkbox" id="securekey-login-network-enable-passkeys" name="securekey_login_network_settings[enable_passkeys]" value="1" <?php checked( '1', (string) $settings['enable_passkeys'] ); ?> /> <?php echo esc_html__( 'Enable passkey authentication network-wide', 'securekey-login' ); ?></label></td>
				</tr>
				<tr>
					<th scope="row"><label for="securekey-login-network-show-login-button"><?php echo esc_html__( 'Show passkey button on wp-login.php', 'securekey-login' ); ?></label></th>
					<td><label><input type="checkbox" id="securekey-login-network-show-login-button" name="securekey_login_network_settings[show_login_button]" value="1" <?php checked( '1', (string) $settings['show_login_button'] ); ?> /></label></td>
				</tr>
				<tr>
					<th scope="row"><label for="securekey-login-network-allow-profile-registration"><?php echo esc_html__( 'Allow passkey registration from profile', 'securekey-login' ); ?></label></th>
					<td><label><input type="checkbox" id="securekey-login-network-allow-profile-registration" name="securekey_login_network_settings[allow_profile_registration]" value="1" <?php checked( '1', (string) $settings['allow_profile_registration'] ); ?> /></label></td>
				</tr>
				<tr>
					<th scope="row"><?php echo esc_html__( 'Enforce passkeys for roles', 'securekey-login' ); ?></th>
					<td>
						<?php foreach ( $wp_roles->roles as $role_key => $role_data ) : ?>
							<label>
								<input type="checkbox" name="securekey_login_network_settings[enforced_roles][]" value="<?php echo esc_attr( $role_key ); ?>" <?php checked( in_array( $role_key, (array) $settings['enforced_roles'], true ) ); ?> />
								<?php echo esc_html( $role_data['name'] ); ?>
							</label><br />
						<?php endforeach; ?>
					</td>
				</tr>
				<tr>
					<th scope="row"><label for="securekey-login-network-rp-id-override"><?php echo esc_html__( 'RP ID override', 'securekey-login' ); ?></label></th>
					<td><input type="text" class="regular-text" id="securekey-login-network-rp-id-override" name="securekey_login_network_settings[rp_id_override]" value="<?php echo esc_attr( (string) $settings['rp_id_override'] ); ?>" /></td>
				</tr>
				<tr>
					<th scope="row"><label for="securekey-login-network-allowed-origins"><?php echo esc_html__( 'Allowed origins', 'securekey-login' ); ?></label></th>
					<td>
						<textarea class="large-text" rows="4" id="securekey-login-network-allowed-origins" name="securekey_login_network_settings[allowed_origins]"><?php echo esc_textarea( (string) $settings['allowed_origins'] ); ?></textarea>
						<p class="description"><?php echo esc_html__( 'One origin per line, e.g. https://example.com. Leave empty to auto-allow RP domain origins.', 'securekey-login' ); ?></p>
					</td>
				</tr>
				<tr>
					<th scope="row"><label for="securekey-login-network-allow-site-overrides"><?php echo esc_html__( 'Allow site-level overrides', 'securekey-login' ); ?></label></th>
					<td><label><input type="checkbox" id="securekey-login-network-allow-site-overrides" name="securekey_login_network_settings[allow_site_overrides]" value="1" <?php checked( '1', (string) $settings['allow_site_overrides'] ); ?> /> <?php echo esc_html__( 'Site admins can override passkey and security settings', 'securekey-login' ); ?></label></td>
				</tr>
				<tr>
					<th scope="row"><label for="securekey-login-network-auto-provision"><?php echo esc_html__( 'Auto-provision new sites', 'securekey-login' ); ?></label></th>
					<td><label><input type="checkbox" id="securekey-login-network-auto-provision" name="securekey_login_network_settings[auto_provision_new_sites]" value="1" <?php checked( '1', (string) $settings['auto_provision_new_sites'] ); ?> /> <?php echo esc_html__( 'Create passkey tables/settings when new sites are created', 'securekey-login' ); ?></label></td>
				</tr>
			</table>

			<?php submit_button( __( 'Save Network Settings', 'securekey-login' ) ); ?>
		</form>
		<?php
	}

	/**
	 * Render audit tab.
	 *
	 * @return void
	 */
	private function render_audit_tab(): void {
		$table = new Passkey_Login_Network_Audit_List_Table();
		$table->prepare_items();
		echo '<form method="get">';
		echo '<input type="hidden" name="page" value="securekey-login-network" />';
		echo '<input type="hidden" name="tab" value="audit" />';
		$table->display();
		echo '</form>';
	}

	/**
	 * Render sites tab.
	 *
	 * @return void
	 */
	private function render_sites_tab(): void {
		$table = new Passkey_Login_Network_Site_List_Table();
		$table->prepare_items();
		echo '<form method="get">';
		echo '<input type="hidden" name="page" value="securekey-login-network" />';
		echo '<input type="hidden" name="tab" value="sites" />';
		$table->display();
		echo '</form>';
	}

	/**
	 * Whitelisted network settings keys.
	 *
	 * @return array<string,bool>
	 */
	private static function allowed_settings_keys(): array {
		$keys = array_keys( Passkey_Login_Settings::network_defaults() );
		return array_fill_keys( $keys, true );
	}
}
