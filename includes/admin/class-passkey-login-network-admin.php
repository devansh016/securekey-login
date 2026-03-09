<?php
/**
 * Network admin settings and audit UI.
 *
 * @package passkey-login
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

if ( ! class_exists( 'WP_List_Table' ) ) {
	require_once ABSPATH . 'wp-admin/includes/class-wp-list-table.php';
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
		add_action( 'network_admin_edit_passkey_login_network_settings', array( $this, 'save_settings' ) );
	}

	/**
	 * Register menu.
	 *
	 * @return void
	 */
	public function menu(): void {
		add_menu_page(
			__( 'Passkey Login', 'passkey-login' ),
			__( 'Passkeys', 'passkey-login' ),
			'manage_network_options',
			'passkey-login-network',
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
			wp_die( esc_html__( 'Permission denied.', 'passkey-login' ) );
		}

		check_admin_referer( 'passkey_login_network_settings' );
		$input = filter_input( INPUT_POST, 'passkey_login_network_settings', FILTER_DEFAULT, FILTER_REQUIRE_ARRAY );
		if ( ! is_array( $input ) ) {
			$input = array();
		}
		$input = wp_unslash( $input );
		$clean = Passkey_Login_Settings::sanitize_network_settings( $input );
		update_site_option( 'passkey_login_network_settings', $clean );

		wp_safe_redirect( network_admin_url( 'admin.php?page=passkey-login-network&tab=settings&updated=1' ) );
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
			<h1><?php echo esc_html__( 'Passkey Login', 'passkey-login' ); ?></h1>
			<nav class="nav-tab-wrapper">
				<a href="<?php echo esc_url( network_admin_url( 'admin.php?page=passkey-login-network&tab=settings' ) ); ?>" class="nav-tab <?php echo 'settings' === $tab ? 'nav-tab-active' : ''; ?>"><?php echo esc_html__( 'Settings', 'passkey-login' ); ?></a>
				<a href="<?php echo esc_url( network_admin_url( 'admin.php?page=passkey-login-network&tab=audit' ) ); ?>" class="nav-tab <?php echo 'audit' === $tab ? 'nav-tab-active' : ''; ?>"><?php echo esc_html__( 'Audit Log', 'passkey-login' ); ?></a>
				<a href="<?php echo esc_url( network_admin_url( 'admin.php?page=passkey-login-network&tab=sites' ) ); ?>" class="nav-tab <?php echo 'sites' === $tab ? 'nav-tab-active' : ''; ?>"><?php echo esc_html__( 'Site Overview', 'passkey-login' ); ?></a>
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
		<form method="post" action="<?php echo esc_url( network_admin_url( 'edit.php?action=passkey_login_network_settings' ) ); ?>">
			<?php wp_nonce_field( 'passkey_login_network_settings' ); ?>
			<h2><?php echo esc_html__( 'Network Settings', 'passkey-login' ); ?></h2>
			<table class="form-table" role="presentation">
				<tr>
					<th scope="row"><label for="passkey-login-network-enable-passkeys"><?php echo esc_html__( 'Enable passkeys', 'passkey-login' ); ?></label></th>
					<td><label><input type="checkbox" id="passkey-login-network-enable-passkeys" name="passkey_login_network_settings[enable_passkeys]" value="1" <?php checked( '1', (string) $settings['enable_passkeys'] ); ?> /> <?php echo esc_html__( 'Enable passkey authentication network-wide', 'passkey-login' ); ?></label></td>
				</tr>
				<tr>
					<th scope="row"><label for="passkey-login-network-show-login-button"><?php echo esc_html__( 'Show passkey button on wp-login.php', 'passkey-login' ); ?></label></th>
					<td><label><input type="checkbox" id="passkey-login-network-show-login-button" name="passkey_login_network_settings[show_login_button]" value="1" <?php checked( '1', (string) $settings['show_login_button'] ); ?> /></label></td>
				</tr>
				<tr>
					<th scope="row"><label for="passkey-login-network-allow-profile-registration"><?php echo esc_html__( 'Allow passkey registration from profile', 'passkey-login' ); ?></label></th>
					<td><label><input type="checkbox" id="passkey-login-network-allow-profile-registration" name="passkey_login_network_settings[allow_profile_registration]" value="1" <?php checked( '1', (string) $settings['allow_profile_registration'] ); ?> /></label></td>
				</tr>
				<tr>
					<th scope="row"><?php echo esc_html__( 'Enforce passkeys for roles', 'passkey-login' ); ?></th>
					<td>
						<?php foreach ( $wp_roles->roles as $role_key => $role_data ) : ?>
							<label>
								<input type="checkbox" name="passkey_login_network_settings[enforced_roles][]" value="<?php echo esc_attr( $role_key ); ?>" <?php checked( in_array( $role_key, (array) $settings['enforced_roles'], true ) ); ?> />
								<?php echo esc_html( $role_data['name'] ); ?>
							</label><br />
						<?php endforeach; ?>
					</td>
				</tr>
				<tr>
					<th scope="row"><label for="passkey-login-network-rp-id-override"><?php echo esc_html__( 'RP ID override', 'passkey-login' ); ?></label></th>
					<td><input type="text" class="regular-text" id="passkey-login-network-rp-id-override" name="passkey_login_network_settings[rp_id_override]" value="<?php echo esc_attr( (string) $settings['rp_id_override'] ); ?>" /></td>
				</tr>
				<tr>
					<th scope="row"><label for="passkey-login-network-allowed-origins"><?php echo esc_html__( 'Allowed origins', 'passkey-login' ); ?></label></th>
					<td>
						<textarea class="large-text" rows="4" id="passkey-login-network-allowed-origins" name="passkey_login_network_settings[allowed_origins]"><?php echo esc_textarea( (string) $settings['allowed_origins'] ); ?></textarea>
						<p class="description"><?php echo esc_html__( 'One origin per line, e.g. https://example.com. Leave empty to auto-allow RP domain origins.', 'passkey-login' ); ?></p>
					</td>
				</tr>
				<tr>
					<th scope="row"><label for="passkey-login-network-allow-site-overrides"><?php echo esc_html__( 'Allow site-level overrides', 'passkey-login' ); ?></label></th>
					<td><label><input type="checkbox" id="passkey-login-network-allow-site-overrides" name="passkey_login_network_settings[allow_site_overrides]" value="1" <?php checked( '1', (string) $settings['allow_site_overrides'] ); ?> /> <?php echo esc_html__( 'Site admins can override passkey and security settings', 'passkey-login' ); ?></label></td>
				</tr>
				<tr>
					<th scope="row"><label for="passkey-login-network-auto-provision"><?php echo esc_html__( 'Auto-provision new sites', 'passkey-login' ); ?></label></th>
					<td><label><input type="checkbox" id="passkey-login-network-auto-provision" name="passkey_login_network_settings[auto_provision_new_sites]" value="1" <?php checked( '1', (string) $settings['auto_provision_new_sites'] ); ?> /> <?php echo esc_html__( 'Create passkey tables/settings when new sites are created', 'passkey-login' ); ?></label></td>
				</tr>
			</table>

			<?php submit_button( __( 'Save Network Settings', 'passkey-login' ) ); ?>
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
		echo '<input type="hidden" name="page" value="passkey-login-network" />';
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
		echo '<input type="hidden" name="page" value="passkey-login-network" />';
		echo '<input type="hidden" name="tab" value="sites" />';
		$table->display();
		echo '</form>';
	}
}
