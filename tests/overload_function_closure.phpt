--TEST--
overload_function() can use a closure as the overload function
--SKIPIF--
<?php 
if (!extension_loaded('test_helpers')) die('skip test_helpers extension not loaded');

if (version_compare(PHP_VERSION, '5.3.0', '<')) die('skip php 5.3 necessary for this test');
?>
--FILE--
<?php

function foo() { echo "FOO"; }

overload_function('foo', function() { echo "BAR!"; });

foo();
--EXPECT--
BAR!