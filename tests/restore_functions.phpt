--TEST--
restore_functions() removes all overload registrations and allows original functions to be called again.
--SKIPIF--
<?php 
if (!extension_loaded('test_helpers')) die('skip test_helpers extension not loaded');
?>
--FILE--
<?php

function my_date($format, $time=NULL)
{
	return "FORMAT: $format";
}

date_default_timezone_set('Europe/Amsterdam');

overload_function('date', 'my_date');
echo date('Y-m-d'), PHP_EOL;

restore_functions();

echo date('Y-m-d', strtotime("2011-02-14 12:00")), PHP_EOL;

--EXPECT--
FORMAT: Y-m-d
2011-02-14
