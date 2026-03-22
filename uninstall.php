<?php
/**
 * Uninstall cleanup for Securekey Login.
 *
 * @package securekey-login
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
function securekey_login_drop_site_tables(): void {
	global $wpdb;

	$securekey_login_tables = array(
		$wpdb->prefix . 'securekey_login_credentials',
		$wpdb->prefix . 'securekey_login_challenges',
	);

	foreach ( $securekey_login_tables as $securekey_login_table ) {
		// phpcs:disable WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching,WordPress.DB.DirectDatabaseQuery.SchemaChange -- Uninstall must drop plugin-owned tables.
		$wpdb->query(
			$wpdb->prepare(
				'DROP TABLE IF EXISTS %i',
				$securekey_login_table
			)
		);
		// phpcs:enable
	}
}

if ( is_multisite() ) {
	$securekey_login_site_ids = get_sites(
		array(
			'fields' => 'ids',
		)
	);

	foreach ( $securekey_login_site_ids as $securekey_login_site_id ) {
		switch_to_blog( (int) $securekey_login_site_id );
		delete_option( 'securekey_login_settings' );
		securekey_login_drop_site_tables();
		restore_current_blog();
	}

	delete_site_option( 'securekey_login_network_settings' );

	$securekey_login_main_prefix  = $wpdb->get_blog_prefix( get_main_site_id() );
	$securekey_login_audit_tables = array(
		$securekey_login_main_prefix . 'securekey_login_network_audit_log',
	);

	foreach ( $securekey_login_audit_tables as $securekey_login_audit_table ) {
		// phpcs:disable WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching,WordPress.DB.DirectDatabaseQuery.SchemaChange -- Uninstall must drop plugin-owned tables.
		$wpdb->query(
			$wpdb->prepare(
				'DROP TABLE IF EXISTS %i',
				$securekey_login_audit_table
			)
		);
		// phpcs:enable
	}
} else {
	delete_option( 'securekey_login_settings' );
	securekey_login_drop_site_tables();
}
