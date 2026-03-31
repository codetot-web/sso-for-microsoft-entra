<?php
/**
 * Admin settings page template.
 *
 * Rendered by Settings_Page::render_page(). All output is escaped.
 *
 * @package MicrosoftEntraSSO
 */

defined( 'ABSPATH' ) || exit;
?>
<div class="wrap messo-settings-wrap">

	<h1><?php echo esc_html( get_admin_page_title() ); ?></h1>

	<?php settings_errors( 'microsoft_entra_sso_settings' ); ?>

	<form method="post" action="options.php" novalidate="novalidate">

		<?php settings_fields( \MicrosoftEntraSSO\Admin\Settings_Page::OPTION_GROUP ); ?>

		<?php do_settings_sections( \MicrosoftEntraSSO\Admin\Settings_Page::PAGE_SLUG ); ?>

		<?php submit_button( __( 'Save Settings', 'microsoft-entra-sso' ) ); ?>

	</form>

</div>
