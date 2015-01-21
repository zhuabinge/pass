<?php
final class session
{
  public static function start()
  {
    global $user;
    session_start();
    if (!isset($_SESSION['user'])) {
      $user = anonymousUser();
    } else {
      $user = $_SESSION['user'];
      unset($_SESSION['user']);
    }
    register_shutdown_function(array('session', 'write'));
  }

  public static function write()
  {
    global $user;
    $_SESSION['user'] = $user;
  }
}
