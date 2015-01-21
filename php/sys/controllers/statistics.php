<?php
class StatisticsController extends BpfController
{
  public function get_statisticsAction()
  {
    $model = $this->getModel('statistics');
    $result = $model->getStatisticsFileInfo();
    $view = $this->getView();
    $view->assign('result',$result);
    $view->display('statistics/get_statistics.phtml');
  }
}
