<?php
class ValueaddModel extends BpfModel
{
  public function getValueAdd($page = 1, $limit = 1)
  {
    $mysqlModel = $this->getModel('mysql');
    $result = $mysqlModel->query('select * from `http_domain` where tag=3 and (state=1 or state=0) limit ' . $limit * ($page - 1) . ',' . $limit)->all();
    return $result;
  }

  public function getValueAddCount()
  {
    $mysqlModel = $this->getModel('mysql');
    $query = $mysqlModel;
    $sql = 'select count(*) from `http_domain` where tag=3 and (state=1 or state=0)';
    return $query->query($sql)->field();
  }

  public function  setValueAdd($set)
  {
    $mysqlModel = $this->getModel('mysql');
    $result1 = $mysqlModel->insert('http_domain', $set, false, true);
    $sid1 = $result1->affected();
    return $sid1;
  }
}
