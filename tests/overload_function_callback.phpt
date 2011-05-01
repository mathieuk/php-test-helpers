--TEST--
overload_function() can use a callback as the overload function
--SKIPIF--
<?php 
if (!extension_loaded('test_helpers')) die('skip test_helpers extension not loaded');

?>
--FILE--
<?php
class bar {
	function tell_me() { echo "BAR!"; }
}

function bar() { echo "BAR!"; }
function foo() { echo "FOO"; }



overload_function('foo', 'bar');
foo();

restore_functions();

$bar = new Bar;
overload_function('foo', array($bar, 'tell_me'));
foo();

--EXPECT--
BAR!BAR!