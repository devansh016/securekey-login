<?php
/**
 * Uninstall cleanup for Passkey Login.
 *
 * @package passkey-login
 */

if ( ! defined( 'WP_UNINSTALL_PLUGIN' ) ) {
	exit;
}

global $wpdb;

/**
 * Drop plugin tables for the current blog.
 *
 * @return void
 */
function passkey_login_drop_site_tables(): void {
	global $wpdb;

	$passkey_login_tables = array(
		$wpdb->prefix . 'passkey_login_credentials',
		$wpdb->prefix . 'passkey_login_challenges',
	);

	foreach ( $passkey_login_tables as $passkey_login_table ) {
		// phpcs:disable WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching,WordPress.DB.DirectDatabaseQuery.SchemaChange -- Uninstall must drop plugin-owned tables.
		$wpdb->query(
			$wpdb->prepare(
				'DROP TABLE IF EXISTS %i',
				$passkey_login_table
			)
		);
		// phpcs:enable
	}
}

if ( is_multisite() ) {
	$passkey_login_site_ids = get_sites(
		array(
			'fields' => 'ids',
		)
	);

	foreach ( $passkey_login_site_ids as $passkey_login_site_id ) {
		switch_to_blog( (int) $passkey_login_site_id );
		delete_option( 'passkey_login_settings' );
		passkey_login_drop_site_tables();
		restore_current_blog();
	}

	delete_site_option( 'passkey_login_network_settings' );

	$passkey_login_main_prefix  = $wpdb->get_blog_prefix( get_main_site_id() );
	$passkey_login_audit_tables = array(
		$passkey_login_main_prefix . 'passkey_login_network_audit_log',
	);

	foreach ( $passkey_login_audit_tables as $passkey_login_audit_table ) {
		// phpcs:disable WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching,WordPress.DB.DirectDatabaseQuery.SchemaChange -- Uninstall must drop plugin-owned tables.
		$wpdb->query(
			$wpdb->prepare(
				'DROP TABLE IF EXISTS %i',
				$passkey_login_audit_table
			)
		);
		// phpcs:enable
	}
} else {
	delete_option( 'passkey_login_settings' );
	passkey_login_drop_site_tables();
}
