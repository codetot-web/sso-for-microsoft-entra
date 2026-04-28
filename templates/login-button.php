<?php
/**
 * Login button template — rendered inside the WordPress login form.
 *
 * Available variables (set by Login_Button::render()):
 *   string $button_text  — Button label, translated and escaped by caller.
 *   string $button_style — 'default', 'dark', or 'light'.
 *   bool   $allow_local  — Whether to show the "use local login" bypass link.
 *   string $sso_url      — Already-escaped URL for the SSO initiation action.
 *   string $local_url    — Already-escaped URL for the local login bypass.
 *
 * @package SFME
 */

defined( 'ABSPATH' ) || exit;

// Map setting value to CSS class. Unknown values fall back to 'default'.
$sfme_valid_styles  = array( 'default', 'dark', 'light' );
$sfme_style_class   = in_array( $button_style, $sfme_valid_styles, true ) ? $button_style : 'default';
$sfme_btn_css_class = ( 'dark' === $sfme_style_class ) ? 'sfme-btn sfme-btn-dark' : 'sfme-btn sfme-btn-light';
?>
<div class="sfme-divider"><?php esc_html_e( 'Or', 'sso-for-microsoft-entra' ); ?></div>

<div class="sfme-btn-wrap">
	<a href="<?php echo esc_url( $sso_url ); // URL already validated by Login_Button::render(). ?>"
		class="<?php echo esc_attr( $sfme_btn_css_class ); ?>"
		role="button"
	>
		<?php
		/*
		 * Microsoft 4-square logo as inline SVG.
		 *
		 * The logo is composed of four coloured squares — this is a geometric
		 * shape, not trademarked artwork, and is widely used in open-source
		 * Microsoft authentication integrations.
		 *
		 * Colors per Microsoft brand guidelines:
		 *   top-left    #f25022 (red)
		 *   top-right   #7fba00 (green)
		 *   bottom-left #00a4ef (blue)
		 *   bottom-right #ffb900 (yellow)
		 */
		?>
		<svg xmlns="http://www.w3.org/2000/svg"
			width="21"
			height="21"
			viewBox="0 0 21 21"
			aria-hidden="true"
			focusable="false"
		>
			<rect x="1"  y="1"  width="9" height="9" fill="#f25022"/>
			<rect x="11" y="1"  width="9" height="9" fill="#7fba00"/>
			<rect x="1"  y="11" width="9" height="9" fill="#00a4ef"/>
			<rect x="11" y="11" width="9" height="9" fill="#ffb900"/>
		</svg>

		<span><?php echo esc_html( $button_text ); ?></span>
	</a>
</div>

<?php if ( $allow_local ) : ?>
<div class="sfme-local-login">
	<a href="<?php echo esc_url( $local_url ); // URL already validated by Login_Button::render(). ?>">
		<?php esc_html_e( 'Use local login instead', 'sso-for-microsoft-entra' ); ?>
	</a>
</div>
<?php endif; ?>
