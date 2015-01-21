<?php
final class cache
{
  private static function getPath()
  {
    static $path = null;
    if (!isset($path)) {
      $path = BpfConfig::get('cache.file.path', '/tmp');
      if (!is_writable($path)) {
        makedir($path, '');
      }
      if ($path) {
        strtr($path, '\\', '/');
        if ($path[strlen($path) - 1] != '/') {
          $path .= '/';
        }
        if (!is_writable($path)) {
          $path = false;
        }
      } else {
        $path = false;
      }
    }
    return $path;
  }

  private static function getFile($cacheId)
  {
    return self::getPath() . $cacheId . '.cache';
  }

  public static function get($cacheId)
  {
    $file = self::getFile($cacheId);
    if (!is_file($file) || !($content = file_get_contents($file))) {
      return false;
    }
    $time = intval(substr($content, 0, 10));
    if (REQUEST_TIME > $time) {
      return false;
    }
    $cache = new stdClass();
    $cache->data = unserialize(substr($content, 11));
    return $cache;
  }

  public static function set($cacheId, $data, $lifetime = null)
  {
    $lifetime = isset($lifetime) ? intval($lifetime) : BpfConfig::get('cache.lifetime', 180);
    $path = self::getPath();
    if (!$path) {
      return false;
    }
    file_put_contents(self::getFile($cacheId), strval(REQUEST_TIME + $lifetime) . ';' . serialize($data));
  }

  public static function remove($cacheId)
  {
    $path = self::getPath();
    if (!$path) {
      return false;
    }
    $file = self::getFile($cacheId);
    if (is_file($file)) {
      unlink($file);
    }
  }

  public static function clear()
  {
    $path = self::getPath();
    if ($path && $dh = opendir($path)) {
      while (false !== ($file = readdir($dh))) {
        if (substr($file, -6) == '.cache') {
          unlink($path . '/' . $file);
        }
      }
    }
  }
}
