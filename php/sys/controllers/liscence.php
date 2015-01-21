<?php
class LiscenceController extends BpfController
{
  public function indexAction()
  {
    $model = $this->getModel('liscence');
    $result = $model->getFileInfo();  // 未注册或过期
    //$result = $model->getUserInfo();  //已注册
    //echo $result;exit();
    $view = $this->getView();
    $view->assign('result',$result);
    $view->display('liscence/add_liscence.phtml');  // 未注册或过期
    //$view->display("liscence/.phtml");  //已注册
  }

  public function addLiscenceAction()
  {
    if(isset($_POST['liscence'])){
      $model = $this->getModel('liscence');
      $result = $model->setFileInfo($_POST['liscence']);
      echo $result;
    }
  }
}
