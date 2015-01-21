<?php
class BusinessModel extends BpfModel
{
  public function getBusiness($conditions = null, $page = 1, $limit = 1)
  {
    $set = array();
    $num = 0;
    $mysqlModel = $this->getModel('mysql');
    $result = $mysqlModel->query('select d.*,count(*) from http_domain d inner join http_rule r on d.do_id = r.do_id group by d.do_id limit ' . $limit * ($page - 1) . ',' . $limit)->all();
    foreach ($result as $value) {
      $set[$num] = get_object_vars($value);
      $num++;
    }
    return $set;
  }

  public function getBusinessCount($conditions)
  {
    $mysqlModel = $this->getModel('mysql');
    $query = $mysqlModel->getSqlBuilder();
    $query->select('COUNT(0)')->from('http_domain')->join('http_rule', 'http_domain.do_id = http_rule.do_id');
    return count($query->groupby('http_domain.do_id')->query()->column());
  }

  public function getDomainById($set)
  {
    $mysqlModel = $this->getModel('mysql');
    $result1 = $mysqlModel->getSqlBuilder()->select('*')->from('http_domain')->where('do_id',$set['do_id'])->query()->all();
    $result = array();
    $result['do_id'] = $result1[0]->do_id;
    $result['domain'] = $result1[0]->domain;
    $result['type'] = $result1[0]->type;
    $result['tag'] = $result1[0]->tag;
    return $result;
  }

  public function getHttpDomain()
  {
    $result = array();
    $set1 = array();
    $num = 0;
    $mysqlModel = $this->getModel('mysql');
    $set1 = $mysqlModel->getSqlBuilder()->select('*')->from('http_domain')->query()->all();
    foreach ($set1 as $value) {
      $result[$num] = get_object_vars($value);
      $num++;
    }
    return $result;
  }

  public function get_HttpDomain()
  {
    $result = array();
    $set1 = array();
    $num = 0;
    $mysqlModel = $this->getModel('mysql');
    $set1 = $mysqlModel->getSqlBuilder()->select('domain')->from('http_domain')->query()->all();
    foreach ($set1 as $value) {
      $result[$num] = get_object_vars($value);
      $num++;
    }
    return $result;
  }

  public function get_HttpData()
  {
    $result = array();
    $set1 = array();
    $num = 0;
    $mysqlModel = $this->getModel('mysql');
    $set1 = $mysqlModel->getSqlBuilder()->select('data_num')->from('http_data')->query()->all();
    foreach ($set1 as $value) {
      $result[$num] = get_object_vars($value);
      $num++;
    }
    return $result;
  }

  public function getHttpRule($set, $conditions = null, $page = 1, $limit = 1)
  {
    $result = array();
    $set1 = array();
    $num = 0;
    $mysqlModel = $this->getModel('mysql');
    if ($set['do_id'] == 0) { //获取所有的rule
      $set1 = $mysqlModel->query('select d.domain,r.* from http_rule r inner join http_domain d on r.do_id=d.do_id limit ' . $limit * ($page - 1) . ',' . $limit)->all();
      foreach ($set1 as $value) {
        $result[$num] = get_object_vars($value);
        $num++;
      }
    } else if ($set['do_id'] > 0) { //根据do_id获取rule数据
      $sql = '';
      if (isset($set['rule_id'])) { //根据rule_id获取数据，用于修改
        $sql = 'select * from `http_rule` where rule_id='.$set['rule_id'];
      } else if (isset($set['flag']) && $set['flag'] == 'true') {
        $sql = 'select d.domain,r.* from `http_rule` r inner join `http_domain` d on r.do_id=d.do_id and r.do_id='.$set['do_id'];
      } else {  //
        $sql = 'select d.domain,r.* from `http_rule` r inner join `http_domain` d on r.do_id=d.do_id and r.do_id='.$set['do_id'].' limit ' . $limit * ($page - 1) . ',' . $limit;
      }
      $set1 = $mysqlModel->query($sql)->all();
      foreach ($set1 as $value) {
        $result[$num] = get_object_vars($value);
        $num++;
      }
    }
    return $result;
  }

  public function getHttpRuleCount($conditions) {
    $mysqlModel = $this->getModel('mysql');
    $query = $mysqlModel->getSqlBuilder();
    $query->select('COUNT(0)')->from('http_domain')->join('http_rule', 'http_domain.do_id = http_rule.do_id');
    if ($conditions['do_id'] > 0){
      $query->where('http_domain.do_id', $conditions['do_id']);
    }
    return $query->query()->field();
  }

  public function getHttpData($set, $conditions = null, $page = 1, $limit = 1)
  {
    $result = array();
    $set1 = array();
    $num = 0;
    $mysqlModel = $this->getModel('mysql');
    if (isset($set['data_num'])) {
      $set1 = $mysqlModel->getSqlBuilder()->select('*')->from('http_data')->where('data_num', $set['data_num'])->limitPage($limit , $page - 1)->query()->all();
    } else {
      $set1 = $mysqlModel->getSqlBuilder()->select('*')->from('http_data')->query()->all();
    }
    foreach ($set1 as $value) {
      $result[$num] = get_object_vars($value);
      $num++;
    }
    return $result;
  }

  public function getHttpDataCount($conditions) {
    $mysqlModel = $this->getModel('mysql');
    $query = $mysqlModel->getSqlBuilder();
    $query->select('COUNT(0)')->from('http_data')->where('data_num', $conditions['data_num']);
    //var_dump( $query->query()->field());exit();
    return $query->query()->field();
  }

  public function delHttp_domain($set)
  {
    $mysqlModel = $this->getModel('mysql');
    $result2 = $mysqlModel->delete('http_rule', $set);
    $sid2 = $result2->affected();
    $result1 = $mysqlModel->delete('http_domain', $set);
    $sid1 = $result1->affected();
    return $sid1;
  }

  public function delHttp_rule($set)
  {
    $mysqlModel = $this->getModel('mysql');
    $result2 = $mysqlModel->delete('http_rule', $set);
    $sid2 = $result2->affected();
    return $sid2;
  }

  public function addHttp_domain( $set)
  {
    $mysqlModel = $this->getModel('mysql');
    $result = $mysqlModel->insert('http_domain', $set, false, true);
    $sid = $result->insertId();
    return $sid;
  }

  public function addHttp_data($set)
  {
    $mysqlModel = $this->getModel('mysql');
    $result = $mysqlModel->insert('http_data', $set, false, true);
    $sid = $result->insertId();
    return $sid;
  }

  public function addHttp_rule( $set)
  {
    $mysqlModel = $this->getModel('mysql');
    $result1 = $mysqlModel->insert('http_rule', $set, false, true);
    if (isset($set['state'])) {
      $set2 = array(
        'state' => $set['state'],
        );
      $set3 = array(
        'do_id' => $set['do_id'],
        );
      $result2 = $mysqlModel->update('http_domain', $set2, $set3);
    }
    $sid = $result1->insertId();
    return $sid;
  }
}
