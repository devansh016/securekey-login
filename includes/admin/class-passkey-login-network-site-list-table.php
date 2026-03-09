<?php
/**
 * Network site overview list table.
 *
 * @package passkey-login
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

if ( ! class_exists( 'WP_List_Table' ) ) {
	require_once ABSPATH . 'wp-admin/includes/class-wp-list-table.php';
}

class Passkey_Login_Network_Site_List_Table extends WP_List_Table {
	/**
	 * Columns.
	 *
	 * @return array<string,string>
	 */
	public function get_columns(): array {
		return array(
			'site_id'          => __( 'Site ID', 'passkey-login' ),
			'domain'           => __( 'Domain', 'passkey-login' ),
			'path'             => __( 'Path', 'passkey-login' ),
			'credential_count' => __( 'Passkeys', 'passkey-login' ),
		);
	}

	/**
	 * Prepare rows.
	 *
	 * @return void
	 */
	public function prepare_items(): void {
		$sites = get_sites( array( 'number' => 100 ) );
		$rows  = array();

		foreach ( $sites as $site ) {
			switch_to_blog( (int) $site->blog_id );
			global $wpdb;
			$table = $wpdb->prefix . 'passkey_login_credentials';
			$count = (int) $wpdb->get_var(
				$wpdb->prepare(
					'SELECT COUNT(*) FROM %i',
					$table
				)
			);
			restore_current_blog();

			$rows[] = array(
				'site_id'          => (int) $site->blog_id,
				'domain'           => $site->domain,
				'path'             => $site->path,
				'credential_count' => $count,
			);
		}

		$this->items           = $rows;
		$this->_column_headers = array( $this->get_columns(), array(), array() );
	}
}
