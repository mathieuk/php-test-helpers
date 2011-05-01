--TEST--
overload_function() is capable of taking over internal functions
--SKIPIF--
<?php 
if (!extension_loaded('test_helpers')) die('skip test_helpers extension not loaded');
?>
--FILE--
<?php
$headers = array();

function my_header($header)
{
    $GLOBALS['headers'][] = $header;
}

overload_function('header', 'my_header');
header('Location: http://www.example.com/');
var_dump($headers);
--EXPECT--
array(1) {
  [0]=>
  string(33) "Location: http://www.example.com/"
}
