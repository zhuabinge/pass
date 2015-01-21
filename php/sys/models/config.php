<?php
/**
 * 应用配置服务类
 * @author Bun <bunwong@qq.com>
 */
class ConfigModel extends BpfModel
{

  /**
  * 生成接口配置文件
  * @return bool
  */
  public function createInterfaceConfig()
  {
    $url = $this->serviceUrl . '/createInterfaceConfig';
    $result = $this->put($url);
    return $result;
  }

  /**
  * 生成HttpData业务配置
  * @return bool
  */
  public function createHttpDataConfig()
  {
    $url = $this->serviceUrl . '/createHttpDataConfig';
    $result = $this->put($url);
    return $result;
  }

  /**
  * 生成HttpRule业务配置
  * @return bool
  */
  public function createHttpRuleConfig()
  {
    $url = $this->serviceUrl . '/createHttpRuleConfig';
    $result = $this->put($url);
    return $result;
  }
}
