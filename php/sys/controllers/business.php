<?php
class BusinessController extends BpfController
{
  /**
  *显示全部业务时获取数据
  */
  public function get_businessAction($page = 1)
  {
    $model = $this->getModel('business');
    $rows = 1; //每页数量
    $condition = array(); //查询的条件
    $set = $model->getBusiness($condition, $page, $rows);
    $allBusinessCount = $model->getBusinessCount($condition);
    $totalPage = ($allBusinessCount / $rows);
    if ($allBusinessCount % $rows > 0 ) {
      $totalPage++;
    }
    if ($page != 1 && $page > $totalPage) { //溢出处理
      gotoUrl('business/get_business/1');
    }
    $view = $this->getView();
    $view->assign('page', is_numeric($page) ? $page : 1);
    $view->assign('rows', $rows);
    $view->assign('count', $allBusinessCount);
    $view->assign('result', $set);
    $view->display('business/get_business.phtml');
  }

  /**
  *进入添加业务的页面时，加载需要显示的数据
  */
  public function initViewAction()
  {
    if (isset($_GET['page'])) {
      $view = $this->getView();
      $model = $this->getModel('business');
      if ($_GET['page'] == 1) {
        $view->display('business/set_domain.phtml');
      } else if($_GET['page'] == 2) {
        $domain = $model->getHttpDomain();
        $view->assign('domainset', $domain);
        $view->display('business/set_data.phtml');
      } else if($_GET['page'] == 3) {
        $domain = $model->getHttpDomain();
        $view->assign('domainset', $domain);
        $view->display('business/set_rule.phtml');
      }
    }
  }

   /**
  *添加domain时，返回已有的domain，用于校验
  */
   public function get_HttpDomainAction()
   {
    $model = $this->getModel('business');
    $domain = $model->get_HttpDomain();
    return json_encode($domain);
  }

   /**
  *添加data时，返回已有的data_num，用于校验
  */
   public function get_HttpDataAction()
   {
    $model = $this->getModel('business');
    $data = $model->get_HttpData();
    return json_encode($data);
  }

   /**
  *根据do_id，返回该do_id的数据并显示，用于修改
  */
   public function getHttpDomainByIdAction()
   {
    if (isset($_GET['do_id'])) {
      $set = array(
        'do_id' => $_GET['do_id'],
        );
      $model = $this->getModel('business');
      $result = $model->getDomainById($set);
      $view = $this->getView();
      $view->assign('domain',$result);
      $view->display('business/set_domain.phtml');
    }
  }

  /**
  *进入添加rule页面时，先加载rule页面须显示的数据
  */
  public function getRuleAction($page = 1)
  {
    if (isset($_GET['do_id']) && isset($_GET['range'])) {
      $set=array(
        'do_id' => $_GET['do_id'],
        );
      $rows = 1; //每页数量
      $condition = array(
        'do_id' => $_GET['do_id'],
        );
      $model = $this->getModel('business');
      $view = $this->getView();
      if ($_GET['range'] == 1) {  //返回该do_id对应的所有rule数据
        $set['flag'] = 'true';
        $http_rule = $model->getHttpRule($set);
        $http_data = $model->getHttpData($set);
        $view->assign('http_rule', $http_rule);
        $view->assign('http_data', $http_data);
        $view->display('business/set_rule_info.phtml');
      } else if ($_GET['range'] == 2) { //返回rule数据
        $http_rule = $model->getHttpRule($set, $condition, $page, $rows);
        $ruleCount = $model->getHttpRuleCount($condition);
        $totalPage = ($ruleCount / $rows);
        if ($ruleCount % $rows > 0 ) {
          $totalPage++;
        }
        if ($page != 1 && $page > $totalPage) { //溢出处理
          gotoUrl('business/getRule/1?do_id='.$_GET['do_id'].'&range=2');
        }
        $view->assign('page', is_numeric($page) ? $page : 1);
        $view->assign('rows', $rows);
        $view->assign('count', $ruleCount);
        $view->assign('do_id', $_GET['do_id']);
        $view->assign('http_rule', $http_rule);
        $view->display('business/get_rule.phtml');
      } else if ($_GET['range'] == 3) { //返回data数据
        $set1 = array(
          'data_num' => $_GET['data_num'],
          );
        $condition['data_num'] = $_GET['data_num'];
        $http_data = $model->getHttpData($set1, $condition, $page, $rows);
        $dataCount = $model->getHttpDataCount($condition);
        $totalPage = ($dataCount / $rows);
        if ($dataCount % $rows > 0 ) {
          $totalPage++;
        }
        if ($page != 1 && $page > $totalPage) { //溢出处理
          gotoUrl('business/getRule/1?do_id='.$_GET['do_id'].'&data_num='.$_GET['data_num'].'&range=3');
        }
        $view->assign('page', is_numeric($page) ? $page : 1);
        $view->assign('rows', $rows);
        $view->assign('count', $dataCount);
        $view->assign('do_id', $_GET['data_num']);
        $view->assign('http_data', $http_data);
        $view->display('business/get_data.phtml');
      }
    }
  }

  public function modify_httpDomainAction()
  {
    if (isset($_GET['do_id'])) {
      $set = array(
        'do_id' => $_GET['do_id'],
        );
      $view = $this->getView();
      $view->assign('set',$set);
      $view->display('business/modify_domain.phtml');
    }
  }

  public function modify_HttpRuleAction()
  {
    if (isset($_GET['do_id']) && isset($_GET['rule_id'])) {
      $set = array(
        'rule_id' => $_GET['rule_id'],
        'do_id' => $_GET['do_id'],
        );
      $view = $this->getView();
      $view->assign('set',$set);
      $view->display('business/modify_rule.phtml');
    }
  }

  public function add_businessAction()
  {
    $set = array();
    $model = $this->getModel('business');
    $view = $this->getView();
    $domain = $model->getHttpDomain();
    $http_data = $model->getHttpData($set);
    $view->assign('http_data', $http_data);
    $view->assign('domainset', $domain);
    $view->display('business/add_business.phtml');
  }

  public function addHttpDomainAction()
  {
    if (isset($_POST['type']) && isset($_POST['domain']) && isset($_POST['tag'])) {
      if ($_POST['type'] == '1') {
        $set =  array( );
        $model = $this->getModel('business');
        $set['domain'] = $_POST['domain'];
        $set['type'] = $_POST['type'];
        $set['tag'] = $_POST['tag'];
        if (isset($_POST['do_id'])) {
          $set['do_id'] = $_POST['do_id'];
          $set['updated'] = REQUEST_TIME;
          $result = $model->addHttp_domain($set);
          gotoUrl('business/get_business');
        } else {
          $set['created'] = REQUEST_TIME;
          $result = $model->addHttp_domain($set);
          gotoUrl('business/add_business');
        }
      }
    }
  }

  public function addHttpDataAction()
  {
    if (isset($_POST['type']) && isset($_POST['do_id']) && isset($_POST['data_num']) && isset($_POST['head']) && isset($_POST['body'])) {
      if ($_POST['type'] == '1') {
        $set =  array( );
        $model = $this->getModel('business');
        $set['do_id'] = $_POST['do_id'];
        $set['data_num'] = $_POST['data_num'];
        $set['head'] = $_POST['head'];
        $set['body'] = $_POST['body'];
        $set['created'] = REQUEST_TIME;
        $result = $model->addHttp_data($set);
        gotoUrl('business/add_business');
      }
    }
  }

  public function addHttpRuleAction()
  {
    if (isset($_POST['type']) && isset($_POST['do_id']) && isset($_POST['data_num']) && isset($_POST['url']) && isset($_POST['cookies']) && isset($_POST['referer'])) {
      if ($_POST['type'] == '1' ) {
        $model = $this->getModel('business');
        $num = 0;
        $count = count($_POST['orders']);
        do {
          if ($num == $_POST['location']) {
            $num++;
            continue;
          } else {
            $set =  array( );
            $set['do_id'] = $_POST['do_id'];
            $set['orders'] = $_POST['orders'][$num];
            $set['data_num'] = $_POST['data_num'][$num];
            $set['url'] = $_POST['url'][$num];
            $set['cookies'] = $_POST['cookies'][$num];
            $set['referer'] = $_POST['referer'][$num];
            if (isset($_POST['rule_id'][$num])) {
              $set['rule_id'] = $_POST['rule_id'][$num];
              $set['updated'] = REQUEST_TIME;
            } else {
              $set['created'] = REQUEST_TIME;
              $set['state'] = 1;
            }
            $result = $model->addHttp_rule($set);
            $num++;
          }
        } while ($num < $count);
        gotoUrl('business/add_business');
      }
    }
  }

  public function del_domainAction()
  {
    if (isset($_GET['do_id'])) {
      $set = array(
        'do_id' => $_GET['do_id'],
        );
      $model = $this->getModel('business');
      $result = $model->delHttp_domain($set);
      gotoUrl('business/get_business');
    }
  }

  public function del_ruleAction()
  {
    if (isset($_GET['rule_id'])) {
      $set = array(
        'rule_id' => $_GET['rule_id'],
        );
      $model = $this->getModel('business');
      $result = $model->delHttp_rule($set);
      return json_encode($result);
    }
  }

  public function makeHttpDataFileAction()
  {
    $model = $this->getModel('config');
    $result = $model->createHttpDataConfig();
    return json_encode($result);
  }

  public function makeHttpRuleFileAction()
  {
    $model = $this->getModel('config');
    $result = $model->createHttpRuleConfig();
    return json_encode($result);
  }
}
