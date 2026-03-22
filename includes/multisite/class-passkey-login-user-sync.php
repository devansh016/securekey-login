<?php
/**
 * User sync/cleanup across network.
 *
 * @package securekey-login
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class Passkey_Login_User_Sync {
	/**
	 * Setup hooks.
	 *
	 * @return void
	 */
	public function init(): void {
		add_action( 'deleted_user', array( $this, 'delete_user_credentials' ), 10, 1 );
	}

	/**
	 * Delete credentials when user is deleted.
	 *
	 * @param int $user_id User ID.
	 * @return void
	 */
	public function delete_user_credentials( int $user_id ): void {
		global $wpdb;
		$table = $wpdb->prefix . 'securekey_login_credentials';

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Plugin credentials must be cleaned up immediately when users are deleted.
		$wpdb->delete( $table, array( 'user_id' => $user_id ), array( '%d' ) );
	}
}
