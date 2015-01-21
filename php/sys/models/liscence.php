<?php
class LiscenceModel extends BpfModel
{
  public function getFileInfo()
  {
    $fp = fopen(dirname(__FILE__) . '/mc.txt', "r");
    $result = fread($fp, filesize(dirname(__FILE__) . '/mc.txt'));
    fclose($fp);
    return $result;
  }

  public function getUserInfo()
  {
    ///
  }

  public function setFileInfo($info)
  {
    $date = date("Y-m-d h:i:s").'.txt';
    $fp = fopen(dirname(__FILE__).'/'.$date, 'w');
    fwrite($fp, $info);
    fclose($fp);
    return 'success';
  }
}
