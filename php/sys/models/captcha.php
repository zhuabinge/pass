<?php
/**
 * 验证码生成类
 * @author Bun <bunwong@qq.com>
 */
class CaptchaModel extends BpfModel
{
  private static $_string = '346789abcdefghijkmnpqrtuvwxyABCDEFGHJKLMNPQRTUVWXY';

  /**
   * 生成验证码
   * @param string $key 验证码标识
   * @param int $len 验证码长度
   * @return string
   */
  public function buildCode($key, $len = 4)
  {
    if (!isset($_SESSION['captcha'])) {
      $_SESSION['captcha'] = array();
    }
    $length = strlen(self::$_string) - 1;
    $code = '';
    for ($i = 0; $i < $len; ++$i) {
      $code .= self::$_string[mt_rand(0, $length)];
    }
    $_SESSION['captcha'][$key] = array(
      'code' => $code,
      'expires' => REQUEST_TIME + 300,  // 5 分钟失效
    );
    return $code;
  }

  /**
   * 检查验证码是否正确
   * @param string $key 验证码标识
   * @param string $code 验证码
   * @return bool
   */
  public function checkCode($key, $code)
  {
    return isset($_SESSION['captcha']) && isset($_SESSION['captcha'][$key]) &&
        0 == strcasecmp($_SESSION['captcha'][$key]['code'], $code) &&
        REQUEST_TIME <= $_SESSION['captcha'][$key]['expires'];
  }

  /**
   * 输出验证码
   * @param string $key 验证码标识
   */
  public function display($key, $weight, $height)
  {
    if (!isset($_SESSION['captcha']) || !isset($_SESSION['captcha'][$key])) {
      return false;
    }
    $weight = min(max(intval($weight), 30), 600);
    $height = min(max(intval($height), 30), 600);
    $im = imagecreatetruecolor($weight, $height);
    $this->_drawBackground($im);
    $fontfile = dirname(__FILE__) . '/captcha_fonts/' . sprintf('%02d', mt_rand(1, 4)) . '.ttf';
    $code = $_SESSION['captcha'][$key]['code'];
    $len = strlen($code);
    $size = mt_rand(20, 25);
    for ($i = 0; $i < $len; ++$i) {
      $color = imagecolorallocate($im, mt_rand(0x00, 0x55), mt_rand(0x00, 0x55), mt_rand(0x00, 0x55));
      imagettftext($im, $size, mt_rand(-30, 30), 20 + 30 * $i + mt_rand(-5, 5), mt_rand(23, 27),
          $color, $fontfile, $code[$i]);
    }
    header('Content-type: image/png');
    imagepng($im);
    imagedestroy($im);
  }

  private function _drawBackground($im)
  {
    $w = imagesx($im);
    $h = imagesy($im);
    imagefill($im, 0, 0, imagecolorallocate($im, 0xff, 0xff, 0xff));
    for($i = 0; $i < 8; ++$i){
      $noiseColor = imagecolorallocate($im, mt_rand(0xaa, 0xee), mt_rand(0xaa, 0xee), mt_rand(0xaa, 0xee));
      for($j = 0; $j < 5; ++$j) {
        imagestring($im, mt_rand(2, 5), mt_rand(-10, $w), mt_rand(-10, $h), randomString(1), $noiseColor);
      }
    }
  }
}
