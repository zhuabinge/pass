<?php
/**
 * 缓存服务类
 * @author Bun <bunwong@qq.com>
 */
class CacheModel extends BpfModel
{
  public function get($key, $default = null, $serialize = true)
  {
    $url = $this->serviceUrl . '/value?' . http_build_query(array(
      'key' => $key,
    ));
    $result = parent::get($url);
    $value = $result && is_object($result) && isset($result->value) ? $result->value : null;
    return $value ? ($serialize ? unserialize($value) : $value) : $default;
  }

  public function keys($key = null)
  {
    $url = $this->serviceUrl . '/keys?' . http_build_query(array(
      'key' => isset($key) ? $key : '*',
    ));
    $result = parent::get($url);
    return $result && is_object($result) && isset($result->keys) ? $result->keys : false;
  }

  public function set($key, $value, $lifetime = null, $serialize = true)
  {
    $url = $this->serviceUrl . '/value?' . http_build_query(array(
      'key' => $key,
    ));
    $params = array(
      'value' => $serialize ? serialize($value) : $value,
      'ex' => intval($lifetime),
    );
    $result = $this->put($url, $params);
    return $result && is_object($result) && isset($result->affected) ? $result->affected : false;
  }

  public function delete($key)
  {
    $args = func_get_args();
    $key = array();
    foreach ($args as $arg) {
      if (is_string($arg)) {
        $key[] = $arg;
      }
    }
    $query = preg_replace('/%5B[0-9]+%5D/simU', '', http_build_query(array('key' => $key)));
    $url = $this->serviceUrl . '/value?' . $query;
    $result = $this->del($url);
    return $result && is_object($result) && isset($result->affected) ? $result->affected : false;
  }

  public function clear()
  {
    return $this->delete('*');
  }
}
