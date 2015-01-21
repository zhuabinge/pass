<?php
class DefaultController extends BpfController
{
  public function indexAction()
  {
    $view = $this->getView();
    $view->assign('page', 1);
    $view->display('index.phtml');
  }

  public function testAction($uid = '')
  {
    echo($_GET['b']);
    echo($uid);
  }
}
