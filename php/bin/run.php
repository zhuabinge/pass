#!/usr/bin/php
<?php
$_SERVER['SCRIPT_NAME'] = '/';
$_SERVER['REQUEST_METHOD'] = 'GET';

define('BINROOT', strtr(dirname(__FILE__), '\\', '/'));
define('BPFROOT', dirname(BINROOT));
define('DOCROOT', BPFROOT . '/html');
define('CNFPATH', BPFROOT . '/etc');
define('LIBPATH', BPFROOT . '/lib');
define('SYSPATH', BPFROOT . '/sys');
define('VARPATH', BPFROOT . '/var');

define('ENV', 'CLI');

if (isset($argv) && isset($argv[1])) {
  $_GET['q'] = $argv[1];
} else {
  die ('Query not found.' . PHP_EOL);
}

require_once LIBPATH . '/core.php';
try {
  BpfCore::init();
  $_SERVER['HTTP_HOST'] = BpfConfig::get('hostname', 'localhost');
  BpfCore::run();
} catch (Exception $ex) {
  BpfCore::errorDispatch($ex);
}
