<?php
define('DOCROOT', strtr(dirname(__FILE__), '\\', '/'));
define('BPFROOT', dirname(DOCROOT));
define('CNFPATH', BPFROOT . '/etc');
define('LIBPATH', BPFROOT . '/lib');
define('SYSPATH', BPFROOT . '/sys');
define('VARPATH', BPFROOT . '/var');
define('ENV', 'WEB');

require LIBPATH . '/core.php';
try {
  BpfCore::init();
  BpfCore::run();
} catch (Exception $ex) {
  BpfCore::errorDispatch($ex);
}
