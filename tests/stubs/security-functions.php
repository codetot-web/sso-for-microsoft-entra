<?php
/**
 * Namespaced function stubs for SFME\Security unit tests.
 *
 * @package SFME\Tests
 */

namespace SFME\Security;

/**
 * Capture setcookie() calls from State_Manager instead of sending headers.
 *
 * @param string $name    Cookie name.
 * @param string $value   Cookie value.
 * @param array  $options Cookie options.
 * @return bool
 */
function setcookie( string $name, string $value = '', array $options = array() ): bool {
	$GLOBALS['_sfme_cookies'][ $name ] = array(
		'value'   => $value,
		'options' => $options,
	);
	return true;
}
