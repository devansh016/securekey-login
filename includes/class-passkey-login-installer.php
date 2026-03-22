<?php
/**
 * Installer.
 *
 * @package securekey-login
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class Passkey_Login_Installer {
	/**
	 * Activate plugin.
	 *
	 * @param bool $network_wide Network activation.
	 * @return void
	 */
	public static function activate( bool $network_wide ): void {
		if ( is_multisite() && $network_wide ) {
			$site_ids = get_sites(
				array(
					'fields' => 'ids',
				)
			);

			foreach ( $site_ids as $site_id ) {
				switch_to_blog( (int) $site_id );
				self::create_site_tables();
				restore_current_blog();
			}

			self::create_network_table();
		} else {
			self::create_site_tables();
			if ( is_multisite() && is_main_site() ) {
				self::create_network_table();
			}
		}

		Passkey_Login_Settings::ensure_defaults();
		Passkey_Login_Capabilities::register();
	}

	/**
	 * Deactivate plugin.
	 *
	 * @return void
	 */
	public static function deactivate(): void {
		Passkey_Login_Capabilities::unregister();
	}

	/**
	 * Create per-site tables.
	 *
	 * @return void
	 */
	public static function create_site_tables(): void {
		global $wpdb;

		require_once ABSPATH . 'wp-admin/includes/upgrade.php';

		$charset_collate = $wpdb->get_charset_collate();
		$credentials     = $wpdb->prefix . 'securekey_login_credentials';
		$challenges      = $wpdb->prefix . 'securekey_login_challenges';

		$sql_credentials = "CREATE TABLE {$credentials} (
			id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
			user_id BIGINT UNSIGNED NOT NULL,
			credential_id VARBINARY(255) NOT NULL,
			public_key LONGTEXT NOT NULL,
			sign_count BIGINT UNSIGNED NOT NULL DEFAULT 0,
			transports VARCHAR(255) DEFAULT '',
			name VARCHAR(191) DEFAULT '',
			created_at DATETIME NOT NULL,
			last_used_at DATETIME NULL,
			PRIMARY KEY (id),
			UNIQUE KEY credential_id (credential_id),
			KEY user_id (user_id)
		) {$charset_collate};";

		$sql_challenges = "CREATE TABLE {$challenges} (
			id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
			user_id BIGINT UNSIGNED NULL,
			challenge_hash CHAR(64) NOT NULL,
			type VARCHAR(40) NOT NULL,
			expires_at DATETIME NOT NULL,
			created_at DATETIME NOT NULL,
			ip_address VARCHAR(45) DEFAULT '',
			PRIMARY KEY (id),
			KEY user_id (user_id),
			KEY type (type),
			KEY expires_at (expires_at)
		) {$charset_collate};";

		dbDelta( $sql_credentials );
		dbDelta( $sql_challenges );
	}

	/**
	 * Create network table in main DB.
	 *
	 * @return void
	 */
	public static function create_network_table(): void {
		global $wpdb;

		require_once ABSPATH . 'wp-admin/includes/upgrade.php';
		$charset_collate = $wpdb->get_charset_collate();

		$main_prefix = is_multisite() ? $wpdb->get_blog_prefix( get_main_site_id() ) : $wpdb->prefix;
		$audit_table = $main_prefix . 'securekey_login_network_audit_log';

		$sql_audit = "CREATE TABLE {$audit_table} (
			id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
			site_id BIGINT UNSIGNED NOT NULL,
			user_id BIGINT UNSIGNED NULL,
			event VARCHAR(80) NOT NULL,
			severity VARCHAR(20) NOT NULL DEFAULT 'info',
			message TEXT NOT NULL,
			meta LONGTEXT NULL,
			created_at DATETIME NOT NULL,
			PRIMARY KEY (id),
			KEY site_id (site_id),
			KEY user_id (user_id),
			KEY event (event),
			KEY created_at (created_at)
		) {$charset_collate};";

		dbDelta( $sql_audit );
	}
}
