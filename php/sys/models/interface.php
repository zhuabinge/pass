<?php
class InterfaceModel extends BpfModel{
  public function getInterface( )
  {
    $mysqlModel = $this->getModel('mysql');
    $result = $mysqlModel->getSqlBuilder()->select('*')->from('interface')->query()->all();
    return $result;
  }

  public function setInterface( $set1, $set2, $set4, $set5)
  {
    //var_dump($set1);var_dump($set2);var_dump($set4);var_dump($set5);exit();
    $mysqlModel = $this->getModel('mysql');
    $result = $mysqlModel->update('interface',$set1, $set2);
    $result3 = $mysqlModel->update('interface',$set4, $set5);
    $sid = $result->affected();
    $set3 = array(
      'inter_id' => $set2['inter_id'],
      );
    if ($set1['type'] == 1) {
      $result1 = $mysqlModel->delete('inpackage',$set3);
      $result2 = $mysqlModel->delete('manage',$set3);
      //var_dump($result1);var_dump($result2);exit();
    } else if ($set1['type'] == 2) {
      $result1 = $mysqlModel->delete('outpackage',$set3);
      $result2 = $mysqlModel->delete('manage',$set3);
      //var_dump($result1);var_dump($result2);exit();
    } else if ($set1['type'] == 3) {
      $result1 = $mysqlModel->delete('outpackage',$set3);
      $result2 = $mysqlModel->delete('inpackage',$set3);
      //var_dump($result1);var_dump($result2);exit();
    }

    return $sid;
  }

  public function setOutpackage($set1, $set2)
  {
    //var_dump($set1);var_dump($set2);exit();
    $mysqlModel = $this->getModel('mysql');
    $result1 = $mysqlModel->insert('outpackage', $set1, false, true);
    $set3 = array(
      'out_left_id' => 1,
      );
    $result2 = $mysqlModel->update('out_left', $set2, $set3);
    $sid = $result2->affected();
    return $sid;
  }

  public function setInpackage( $set)
  {
    //var_dump($set);exit();
    $mysqlModel = $this->getModel('mysql');
    $result = $mysqlModel->insert('inpackage', $set, false, true);
    $set1 = array(
      'state' => 1,
      );
    $set2 = array(
      'inter_id' => $set['inter_id2'],
      );
    $result1 = $mysqlModel->update('interface', $set1, $set2);
    $sid = $result->affected();
    return $sid;
  }

  public function setManage( $set)
  {
    $mysqlModel = $this->getModel('mysql');
    $result = $mysqlModel->insert('manage', $set, false, true);
    $sid = $result->affected();
    return $sid;
  }

  public function getManage( $id)
  {
    $result = array();
    $result1 = array();
    $num = 0;
    $mysqlModel = $this->getModel('mysql');
    $set = $mysqlModel->getSqlBuilder()->select('*')->from('manage')->where("inter_id",$id)->query()->all();
    foreach ($set as $value) {
      $result[$num] = get_object_vars($value);
      $num++;
    }
    if (count($result) > 0) {
      $result1 = $result[0];
    } else {
      $result1 = $result;
    }
    //var_dump($result1);exit();
    return $result1;
  }

  public function getOutpackage($id)
  {
    $result = array();
    //$result1 = array();
    $num = 0;
    $mysqlModel = $this->getModel('mysql');
    $set1 = $mysqlModel->getSqlBuilder()->select('*')->from('outpackage')->where("inter_id",$id)->query()->all();
    $result2 = $mysqlModel->getSqlBuilder()->select('*')->from('out_left')->query()->all();
    foreach ($set1 as $value) {
      $result[$num] = get_object_vars($value);
      $num++;
    }
    if ($num > 0) {
      $result[0]['out_left_sum'] = $result2[0]->out_left_num + $result[0]['out_num'];
    } else {
      $result[0]['out_left_sum'] = $result2[0]->out_left_num;
    }
    //var_dump($result[0]);exit();
    return $result[0];
  }

  public function getInpackage( $id)
  {
    $result = array();
    $result1 = array();
    $set1 = array();
    $num = 0;
    $mysqlModel = $this->getModel('mysql');
    $set = $mysqlModel->getSqlBuilder()->select('*')->from('inpackage')->where("inter_id", $id)->query()->all();
    foreach ($set as $value) {
      $result[$num] = get_object_vars($value);
      $num++;
    }
    $num = 0;
    if (isset($result[0]) && $result[0]['inter_id2']) {
      $set1 = $mysqlModel->query('select inter_id,name from `interface` where (type=1 and state=0) or inter_id='.$result[0]['inter_id2'])->all();
    } else {
      $set1 = $mysqlModel->query('select inter_id,name from `interface` where type=1 and state=0')->all();
    }
    foreach ($set1 as $value) {
      $result1[$num] = get_object_vars($value);
      $num++;
    }
    $result[0]['inter_id_set'] = $result1;
    //var_dump($set1);exit();
    return $result[0];
  }

  public function getData($name)
  {
    $mysqlModel = $this->getModel('mysql');
    $result = $mysqlModel->getSqlBuilder()->select('*')->from('interface')->where('name', $name)->query()->all();
    return $result;
  }

  public function getMainConfig()
  {
    $mysqlModel = $this->getModel('mysql');
    $result = $mysqlModel->query('select * from `main_config`')->all();
    //var_dump(count($result));exit();
    return $result;
  }

  public function addMainConfig($set)
  {
    $mysqlModel = $this->getModel('mysql');
    $result = $mysqlModel->insert('main_config', $set, false, true);
    $sid = $result->affected();
    return $sid;
  }
}
