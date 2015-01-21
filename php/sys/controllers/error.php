<?php
class ErrorController extends BpfController
{
  public function errorAction(Exception $ex)
  {
    if ($ex instanceof Bpf503Exception) {
      if (ENV == 'WEB') {
        header('HTTP/1.1 503 Service Unavailable');
      }
      $title = '服务不可用';
    } else if ($ex instanceof Bpf403Exception) {
      if (ENV == 'WEB') {
        header('HTTP/1.1 403 Forbidden');
      }
      $title = '无权访问';
    } else if ($ex instanceof Bpf404Exception) {
      if (ENV == 'WEB') {
        header('HTTP/1.1 404 Not Found');
      }
      $title = '找不到页面';
    } else if ($ex instanceof BpfException) {
      $title = '系统错误';
    } else {
      $title = '未知错误';
    }
    $view = $this->getView();
    $view->assign(array(
      'title' => $title,
      'exception' => $ex,
    ));
    return $view->fetch('error.phtml');
  }
}
