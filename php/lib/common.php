<?php
define('U_ANONYMOUS', 0);

function timer()
{
  static $timer = null;
  if (!isset($timer)) {
    $timer = microtime(true);
    return 0;
  } else {
    $startTimer = $timer;
    $timer = microtime(true);
    return $timer - $startTimer;
  }
}

function anonymousUser($sid = null)
{
  $user = new stdClass();
  $user->uid = U_ANONYMOUS;
  $user->sid = isset($sid) ? $sid : session_id();
  return $user;
}

function isLogin()
{
  global $user;
  return isset($user) && isset($user->uid) && $user->uid != U_ANONYMOUS;
}

function isAdmin()
{
  global $user;
  return isset($user) && isset($user->admin) && $user->admin;
}

function isMerchant()
{
  global $user;
  return isset($user) && isset($user->merchant) && $user->merchant;
}

function isAdminLogin()
{
  global $user;
  return isset($user) && isset($user->adminTime) && REQUEST_TIME - $user->adminTime <= 1800;
}

function makedir($path, $root = DOCROOT)
{
  $path = explode('/', trim($path, '/'));
  while ($dir = array_shift($path)) {
    $root .= '/' . $dir;
    if (!is_dir($root)) {
      mkdir($root);
    }
  }
}

function ipAddress($returnLong = false)
{
  static $ipAddress = null;
  static $ipAddressLong = null;
  if (!isset($ipAddress)) {
    if (isset($_SERVER['HTTP_CLIENT_IP'])) {
      $ipAddress = $_SERVER['HTTP_CLIENT_IP'];
    } else if (isset($_SERVER['HTTP_X_FORWARDED_FOR'])) {
      $ipAddress = $_SERVER['HTTP_X_FORWARDED_FOR'];
    } else {
      $ipAddress = $_SERVER['REMOTE_ADDR'];
    }
  }
  if ($returnLong) {
    if (!isset($ipAddressLong)) {
      $ipAddressLong = ip2long($ipAddress);
    }
    return $ipAddressLong;
  } else {
    return $ipAddress;
  }
}

function url($path, $includeDomain = false)
{
  static $domainUrl = null;
  if (!isset($domainUrl)) {
    $domainUrl = ((isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] == 'on') ? 'https' : 'http') .
        '://' . strtolower($_SERVER['HTTP_HOST']);
  }
  if (!strcasecmp(substr($path, 0, 7), 'http://') || !strcasecmp(substr($path, 0, 8), 'https://')) {
    return $path;
  }
  return ($includeDomain ? $domainUrl : '') . $GLOBALS['basePath'] . ltrim($path, '/');
}


function gotoUrl($path, $httpCode = 302)
{
  if (ENV != 'WEB') {
    return;
  }
  if (strcasecmp('http://', substr($path, 0, 7)) && strcasecmp('https://', substr($path, 0, 8))) {
    $path = url($path, false);
  }
  header('Location: ' . $path, true, $httpCode);
  exit;
}

function randomString($len, $type = null)
{
  $randstring = '1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';
  if (isset($type)) {
    if ($type == 10 || $type == 16) {
      $randstring = substr($randstring, 0, $type);
    } else if ($type == 'a') {
      $randstring = substr($randstring, 10);
    }
  }
  $length = strlen($randstring) - 1;
  $result = '';
  for ($i = 0; $i < $len; ++$i) {
    $result .= $randstring[mt_rand(0, $length)];
  }
  return $result;
}

function plain($text)
{
  return htmlspecialchars($text, ENT_QUOTES);
}

function passTime($timestamp)
{
  $timeDiff = REQUEST_TIME - $timestamp;
  if ($timeDiff < 0) {
    return '未来';
  } else if ($timeDiff < 60) {
    return '刚刚';
  } else if ($timeDiff < 3600) {
    return ceil($timeDiff / 60) . '分钟前';
  } else if ($timeDiff < 86400) {
    return ceil($timeDiff / 3600) . '小时前';
  } else {
    return ceil($timeDiff / 86400) . '天前';
  }
}

function getMessages($clear = true)
{
  if (!isset($_SESSION['bpf_msgs'])) {
    return array();
  }
  $messages = $_SESSION['bpf_msgs'];
  if ($clear) {
    unset($_SESSION['bpf_msgs']);
  }
  return $messages;
}

function setMessage($value, $type = 'info')
{
  if (!isset($_SESSION['bpf_msgs'])) {
    $_SESSION['bpf_msgs'] = array();
  }
  $_SESSION['bpf_msgs'][] = array(
    'type' => $type,
    'value' => $value,
  );
}

function access($permission, $mode = 'and')
{
  global $user;
  $permissions = $user->permissions;
  if (is_array($permission)) {
    if ($mode == 'or') {
      foreach ($permission as $one) {
        if (in_array($one, $permissions)) {
          return true;
        }
      }
      return false;
    } else {
      foreach ($permission as $one) {
        if (!in_array($one, $permissions)) {
          return false;
        }
      }
      return true;
    }
  } else {
    return in_array($permission, $permissions);
  }
}

function getAssocArray(array $array, $key = null)
{
  if (empty($array)) {
    return array();
  }
  if (!isset($key)) {
    $key = key(current($array));
  }
  $result = array();
  array_walk($array, function($value) use ($key, &$result) {
    if (is_object($value) && isset($value->{$key})) {
      $result[$value->{$key}] = $value;
    } else if (is_array($value) && isset($value[$key])) {
      $result[$value[$key]] = $value;
    }
  });
  return $result;
}

function urlProduct($product, $type = null)
{
  $productId = date('Ym', $product->created) . str_pad(dechex($product->pid + 22334456), 8, '0', STR_PAD_LEFT);
  if ($type == 'click') {
    return url('product/click/' . $productId . '.html', true);
  }
  return url('item/' . $productId . '.html', true);
}

function urlCategory($category)
{
  if (is_object($category)) {
    return url('cate/' . ($category->seo_path == '' ? $category->cid : ($category->seo_path . '.html')), true);
  }
  return url('cate/' . $category);
}

function urlChannel($channel)
{
  if (is_object($channel)) {
    return url('topic/' . ($channel->seo_path == '' ? $channel->cid : ($channel->seo_path . '.html')), true);
  }
  return url('topic/' . $channel);
}

function urlTag($tagId)
{
  if (is_object($tagId)) {
    $tagId = $tagId->tid;
  }
  return url('tag/' . $tagId, true);
}

function urlUser($userId, $userUrl = null)
{
  if (is_object($userId)) {
    $userId = $userId->uid;
  }
  $userId = str_pad(dechex($userId + 33445567), 8, '0', STR_PAD_LEFT);
  if (empty($userUrl)) {
    return url('user/likes/' . $userId . '.html', true);
  } else {
    return url($userUrl . $userId . '.html', true);
  }
}

function urlAvatar($user, $size = 50)
{
  return $user && $user->uid && $user->avatar_file_id ? urlStatic($user->avatar_file_path, $size, $size) :
      url('static/default/images/avatar_' . $size . '.jpg', true);
}

function urlAd($adId, $socketId)
{
  if (is_object($adId)) {
    $adId = $adId->aid;
  }
  return url('adclick?token=' . urlencode(base64_encode(sprintf('%08d-%s', $adId, trim($socketId)))), true);
}

function maskString($string, $type = null)
{
  if ($type == 'email') {
    $domain = mb_strrchr($string, '@');
    return maskString(mb_substr($string, 0, -mb_strlen($domain))) . $domain;
  } else {
    $len = mb_strlen($string, 'utf8');
    if ($len < 3) {
      return mb_substr($string, 0, 1) . '***';
    } else {
      $charLen = intval($len / 3);
      $maskLen = $len - $charLen - $charLen;
      return mb_substr($string, 0, $charLen) . str_repeat('*', $maskLen) . mb_substr($string, -$charLen);
    }
  }
  return $string;
}

function dataFormat($temp, $count)
{
  $str = '';
  for ($i = 1; $i < $count; $i++) {
    $flag = 0;
    foreach ( $temp as $value) {
      if ($value == $i) {
        $str = $str.$i;
        $flag = 1;
        break;
      }
    }
    if ($flag == 0) {
      $str = $str.'0';
    }
  }
  return $str;
}
