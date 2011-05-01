--TEST--
overload_function() is capable of taking over user defined functions
--SKIPIF--
<?php 
if (!extension_loaded('test_helpers')) die('skip test_helpers extension not loaded');
?>
--FILE--
<?php
function foo()
{
    print 'foo';
}

function bar()
{
	print 'bar';
}
overload_function('foo', 'bar');
foo();
--EXPECT--
bar
