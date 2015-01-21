<?php
class InterfaceController extends BpfController
{
  public function indexAction()
  {
    $model = $this->getModel('interface');
    $result1 = $model->getInterface();
    $view = $this->getView();
    $view->assign("result",$result1);
    $view->display("interface/set_interface.phtml");
  }

  public function setInterfaceAction(){
    $set1 =  array();
    $set2 =  array();
    $result1 = -1;
    $result2 = -1;
    $model = $this->getModel('interface');
    if (isset($_POST['type']) && ($_POST['type'] == 1 || $_POST['type'] == 2 || $_POST['type'] == 3)) {
      if (isset($_POST['inter_id'])) {
        $set1['type'] = $_POST['type'];
        $set1['updated'] = REQUEST_TIME;
        $set3['inter_id'] = $_POST['inter_id'];
        $set4 = array();
        $set5 = array();
        if (isset($_POST['old_inter_id2'])) {
          if ($_POST['old_inter_id2'] > 0) {
            $set4['state'] = 0;
            $set5['inter_id'] = $_POST['old_inter_id2'];
          }
        }
        $result1 = $model->setInterface($set1, $set3, $set4, $set5);
      }
      if ($_POST['type'] == 1) {
        if (isset($_POST['inter_id']) && isset($_POST['out_num'])) {
          if (isset($_POST['out_id'])) {
            $set2['out_id'] = $_POST['out_id'];
            $set2['updated'] = REQUEST_TIME;
          } else {
            $set2['created'] = REQUEST_TIME;
          }
          $set2['inter_id'] = $_POST['inter_id'];
          $set2['out_num'] = $_POST['out_num'];
          $set4['out_left_num'] = $_POST['out_left_sum'] - $_POST['out_num'];
          $result2 = $model->setOutpackage($set2, $set4);
        }
      } else if ($_POST['type'] == 2) {
        if (isset($_POST['inter_id']) && isset($_POST['type2']) && isset($_POST['inter_id2']) && isset($_POST['analysiser'])) {
          if (isset($_POST['in_id'])) {
            $set2['in_id'] = $_POST['in_id'];
            $set2['updated'] = REQUEST_TIME;
          } else {
            $set2['created'] = REQUEST_TIME;
          }
          if (isset($_POST['type1'])){
            $set2['type1'] = dataFormat($_POST['type1'], 3);
          } else {
            $set2['type1'] = '00';
          }
          $set2['inter_id'] = $_POST['inter_id'];
          $set2['inter_id2'] = $_POST['inter_id2'];
          $set2['analysiser'] = $_POST['analysiser'];
          $set2['type2'] = $_POST['type2'];
          if ($set2['type2'] == 2) {
            if ($_POST['type3'] == 1) {
              $set2['type3'] = '10';
            } else if ($_POST['type3'] == 2) {
              $set2['type3'] = '02';
            }
          } else {
            $set2['type3'] = '00';
          }
          $result2 = $model->setInpackage($set2);
          //gotoUrl("interface/makeInterfaceFile");
        }
      } else if ($_POST['type'] == 3) {
        if (isset($_POST['inter_id']) && isset($_POST['ip']) && isset($_POST['mask']) && isset($_POST['gateway']) && isset($_POST['dns1']) && isset($_POST['dns2'])) {
          if (isset($_POST['ma_id'])) {
            $set2['ma_id'] = $_POST['ma_id'];
            $set2['updated'] = REQUEST_TIME;
          } else {
            $set2['created'] = REQUEST_TIME;
          }
          $set2['inter_id'] = $_POST['inter_id'];
          $set2['ip'] = $_POST['ip'];
          $set2['mask'] = $_POST['mask'];
          $set2['gateway'] = $_POST['gateway'];
          $set2['dns1'] = $_POST['dns1'];
          $set2['dns2'] = $_POST['dns2'];
          $result2 = $model->setManage($set2);
        }
      }
    }
    gotoUrl("interface");
  }

  public function getInterfaceByNameAction()
  {
    if (isset($_GET['name'])) {
      $view = $this->getView();
      $model = $this->getModel('interface');
      $result1 = $model->getData($_GET['name']);
      if (count($result1) > 0) {
        $view->assign("result1",$result1[0]);
      } else {
        $view->assign("result1",$result1);
      }
      $view->display('interface/data.phtml');
    }
  }

  public function getInterfaceViewAction()
  {
    if (isset($_POST['type']) && isset($_POST['inter_id']) && isset($_POST['page'])) {
      $type = $_POST['type'];
      $inter_id = $_POST['inter_id'];
      $page = $_POST['page'];
      $result2 = array();
      $result = array();
      $model = $this->getModel('interface');
      if ($type == 1) {
        $result2 = $model->getOutpackage($inter_id);
      }
      if ($type == 2) {
        $result2 = $model->getInpackage($inter_id);
      } else if ($type == 3) {
        $result2 = $model->getManage($inter_id);
      }
      //var_dump($result2['inter_id_set']);exit();
      $view = $this->getView();
      $view->assign('result2',$result2);
      $view->assign('inter_id',$inter_id);
      if ($page == '1') {
        $view->display('interface/out_package.phtml');
      } else if($page == '2') {
        $view->display('interface/in_package.phtml');
      } else if($page == '3') {
        $view->display('interface/manage.phtml');
      }
    }
  }

  public function mainConfigAction()
  {
    $view = $this->getView();
    $model = $this->getModel('interface');
    $result = $model->getMainConfig();
    //var_dump(count($result));exit();
    if(count($result) > 0){
      $view->assign('result', $result[0]);
    }
    $view->display('interface/main_config.phtml');
  }

  public function addMainConfigAction()
  {
    if (isset($_POST['max_dns_pkt_size']) && isset($_POST['max_http_pkt_size'])
      && isset($_POST['max_send_size']) && isset($_POST['max_log_len'])
      && isset($_POST['watermask']) && isset($_POST['http_spoofers'])
      && isset($_POST['dns_spoofers']) && isset($_POST['max_send_size_type'])
      && isset($_POST['http_method'])) {
      $set = array();
      if (isset($_POST['main_id']) ) {
        $set['main_id'] = $_POST['main_id'];
        $set['updated'] = REQUEST_TIME;
      } else {
        $set['created'] = REQUEST_TIME;
      }
      $set['max_dns_pkt_size'] = $_POST['max_dns_pkt_size'];
      $set['max_http_pkt_size'] = $_POST['max_http_pkt_size'];
      $set['max_send_size'] = $_POST['max_send_size'];
      $set['max_send_size_type'] = $_POST['max_send_size_type'];
      $set['max_log_len'] = $_POST['max_log_len'];
      $set['watermask'] = $_POST['watermask'];
      $set['http_spoofers'] = $_POST['http_spoofers'];
      $set['dns_spoofers'] = $_POST['dns_spoofers'];
      $set['http_method'] = dataFormat($_POST['http_method'], 10);
      $view = $this->getView();
      $model = $this->getModel('interface');
      $result = $model->addMainConfig($set);
      gotoUrl('interface/mainConfig');
    }
  }

  public function makeInterfaceFileAction()
  {
    $model = $this->getModel('config');
    $result = $model->createInterfaceConfig();
    return json_encode($result);
  }
}
