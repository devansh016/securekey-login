<?php
/**
 * User sync/cleanup across network.
 *
 * @package passkey-login
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
		$table = $wpdb->prefix . 'passkey_login_credentials';

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery -- plugin credentials must be cleaned up when users are deleted.
		$wpdb->delete( $table, array( 'user_id' => $user_id ), array( '%d' ) );
	}
}
