<?php
/**
 * Network audit list table.
 *
 * @package passkey-login
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

if ( ! class_exists( 'WP_List_Table' ) ) {
	require_once ABSPATH . 'wp-admin/includes/class-wp-list-table.php';
}

class Passkey_Login_Network_Audit_List_Table extends WP_List_Table {
	/**
	 * Columns.
	 *
	 * @return array<string,string>
	 */
	public function get_columns(): array {
		return array(
			'created_at' => __( 'Time', 'passkey-login' ),
			'site_id'    => __( 'Site', 'passkey-login' ),
			'user_id'    => __( 'User', 'passkey-login' ),
			'event'      => __( 'Event', 'passkey-login' ),
			'severity'   => __( 'Severity', 'passkey-login' ),
			'message'    => __( 'Message', 'passkey-login' ),
		);
	}

	/**
	 * Prepare rows.
	 *
	 * @return void
	 */
	public function prepare_items(): void {
		global $wpdb;
		$per_page     = 20;
		$current_page = $this->get_pagenum();
		$offset       = ( $current_page - 1 ) * $per_page;
		$main_prefix  = $wpdb->get_blog_prefix( get_main_site_id() );
		$table        = $main_prefix . 'passkey_login_network_audit_log';

		$this->items = $wpdb->get_results(
			$wpdb->prepare(
				'SELECT id, site_id, user_id, event, severity, message, created_at FROM %i ORDER BY id DESC LIMIT %d OFFSET %d',
				$table,
				$per_page,
				$offset
			),
			ARRAY_A
		);

		$total_items = (int) $wpdb->get_var(
			$wpdb->prepare(
				'SELECT COUNT(*) FROM %i',
				$table
			)
		);

		$this->_column_headers = array( $this->get_columns(), array(), array() );
		$this->set_pagination_args(
			array(
				'total_items' => $total_items,
				'per_page'    => $per_page,
			)
		);
	}
}
