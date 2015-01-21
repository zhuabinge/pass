<?php
/**
 * MySQL 服务类
 * @author Bun <bunwong@qq.com>
 */
class MysqlModel extends BpfModel
{
  private $_queries = array();

  private function _isSelect($sql)
  {
    return preg_match('/^\s*(?:SELECT|SHOW)\s/i', $sql);
  }

  /**
   * @param string $sql
   * @return BpfQueryResult / BpfExecuteResult
   */
  public function query($sql)
  {
    $params = array(
      'sql' => $sql,
    );
    $this->_queries[] = $sql;
    if ($this->_isSelect($sql)) {
      $url = $this->serviceUrl . '/query';
      return new BpfQueryResult($sql, $this->post($url, $params));
    } else {
      $url = $this->serviceUrl . '/execute';
      return new BpfExecuteResult($sql, $this->post($url, $params));
    }
  }

  /**
   * query 别名
   */
  public function execute($sql)
  {
    return $this->query($sql);
  }

  private function _getKeyValues($set)
  {
    $keys = array();
    $values = array();
    if (!is_array(reset($set))) {
      $set = array($set);
    }
    $i = 0;
    foreach ($set as $r) {
      $row = array();
      foreach ($r as $key => $value) {
        if ($i == 0) {
          $keys[] = '`' . $this->escape($key) . '`';
        }
        $field = true;
        if (is_array($value) && isset($value['value'])) {
          if (isset($value['escape']) && false === $value['escape']) {
            $field = false;
          }
          $value = $value['value'];
        }
        if ($field) {
          $value = '"' . $this->escape($value) . '"';
        }
        $row[] = $value;
      }
      $values[] = '(' . implode(', ', $row) . ')';
      ++$i;
    }
    return array(
      'keys' => $keys,
      'values' => $values,
    );
  }

  public function insert($table, $set, $ignore = false, $duplicateUpdate = false)
  {
    if (!$set || !is_array($set)) {
      return new BpfExecuteResult(null, false);
    }
    $keyValues = $this->_getKeyValues($set);
    $sql = 'INSERT ' . ($ignore ? 'IGNORE ' : '') . 'INTO `' . $this->escape($table) . '` (' .
        implode(', ', $keyValues['keys']) . ') VALUES ' . implode(', ', $keyValues['values']);
    if ($duplicateUpdate) {
      $sql .= ' ON DUPLICATE KEY UPDATE ';
      $fields = array();
      foreach ($keyValues['keys'] as $key) {
        $fields[] = $key . ' = VALUES(' . $key . ')';
      }
      $sql .= implode(', ', $fields);
    }
    return $this->query($sql);
  }

  public function replace($table, $set)
  {
    if (!$set || !is_array($set)) {
      return new BpfExecuteResult(null, false);
    }
    $keyValues = $this->_getKeyValues($set);
    $sql = 'REPLACE INTO `' . $this->escape($table) . '` (' .
        implode(', ', $keyValues['keys']) . ') VALUES ' . implode(', ', $keyValues['values']);
    return $this->query($sql);
  }

  private $_whereRec = array();

  private function _where($cond, $value, $type = 'and', $escape = true)
  {
    static $types = array(
      'and' => 'AND',
      'or'  => 'OR',
    );
    static $ops = array('>=', '<=', '<>', '!=', '=', '>', '<', 'IN', 'LIKE');
    $cond = trim($cond);
    if (false !== ($eqPos = strpos($cond, ' '))) {
      $field = trim(substr($cond, 0, $eqPos));
      $op = strtoupper(trim(substr($cond, $eqPos + 1)));
      if (!in_array($op, $ops)) {
        $op = '=';
      }
    } else {
      $field = $cond;
      $op = '=';
    }
    if ($op == 'IN') {
      if (is_array($value)) {
        foreach ($value as &$v) {
          $v = '"' . $this->escape($v) . '"';
        }
        $value = '(' . implode(', ', $value) . ')';
      } else {
        $op = '=';
        $value = '"' . $this->escape($value) . '"';
      }
    } else {
      if ($escape) {
        $value = '"' . $this->escape($value) . '"';
      }
    }
    $this->_whereRec[] = array(
      'field' => $field,
      'op'    => $op,
      'type'  => $types[$type],
      'value' => $value,
    );
    return $this;
  }

  private function _compileWhere()
  {
    $sql = '';
    $rec = $this->_whereRec;
    if (isset($rec[0])) {
      $sql .= ' ' . 'WHERE';
      foreach ($rec as $num => $cond) {
        if ($num > 0){
          $sql .= ' ' . $cond['type'];
        }
        if (false === strpos($cond['field'], '.')) {
          $sql .= ' `' . $cond['field'] . '`';
        } else {
          $sql .= ' ' . $cond['field'];
        }
        $sql .=  ' ' . $cond['op'] . ' ' . $cond['value'];
      }
    }
    return $sql;
  }

  public function update($table, $set, $where = null)
  {
    if (!$set || !is_array($set)) {
      return new BpfExecuteResult(null, false);
    }
    $values = array();
    foreach ($set as $key => $value) {
      $field = true;
      if (is_array($value) && isset($value['value'])) {
        if (isset($value['escape']) && false === $value['escape']) {
          $field = false;
        }
        $value = $value['value'];
      }
      $value = $this->escape($value);
      if ($field) {
        $value = '"' . $value . '"';
      }
      $values[] = '`' . $this->escape($key) . '` = ' . $value;
    }
    if (is_array($where)) {
      foreach ($where as $key => $value) {
        $this->_where($key, $value);
      }
      $where = $this->_compileWhere('WHERE');
      $this->_whereRec = array();
    } else {
      $where = '';
    }
    $sql = 'UPDATE `' . $this->escape($table) . '` SET ' . implode(', ', $values) . $where;
    return $this->query($sql);
  }

  public function delete($table, $where = null)
  {
    if (is_array($where)) {
      foreach ($where as $key => $value) {
        $this->_where($key, $value);
      }
      $where = $this->_compileWhere('WHERE');
      $this->_whereRec = array();
    } else {
      $where = '';
    }
    $sql = 'DELETE FROM `' . $this->escape($table) . '`' . $where;
    return $this->query($sql);
  }

  public function escape($str)
  {
    return strtr($str, array(
      "\\" => "\\\\",
      "\0" => "\\0",
      "\n" => "\\n",
      "\r" => "\\r",
      "\x1a" => "\Z",
      "'" => "\'",
      "\"" => "\\\"",
    ));
  }

  public function getQueries()
  {
    return $this->_queries;
  }

  public function getSqlBuilder()
  {
    return new BpfSqlBuilder($this);
  }
}

class BpfSqlBuilder
{
  private $_activeRec;
  private $_proxyInstance;

  function __construct($proxyInstance)
  {
    $this->_proxyInstance = $proxyInstance;
    $this->_resetSelect();
  }

  private function _resetSelect()
  {
    $this->_activeRec = array(
      'SELECT' => array(),
      'DISTINCT' => false,
      'FROM' => array(),
      'WHERE' => array(),
      'JOIN' => array(),
      'ORDERBY' => array(),
      'GROUPBY' => array(),
      'HAVING' => array(),
      'LIMIT' => null,
      'OFFSET' => null,
    );
  }

  public function select($select)
  {
    $select = explode(',', $select);
    foreach ($select as $field) {
      $this->_activeRec['SELECT'][] = trim($field);
    }
    return $this;
  }

  public function distinct()
  {
    $this->_activeRec['DISTINCT'] = true;
    return $this;
  }

  public function from($table)
  {
    if (!is_array($table)) {
      $table = array($table);
    }
    foreach ($table as $alias => $name) {
      if (!is_int($alias)) {
        $name .= ' AS ' . $alias;
      }
      $this->_activeRec['FROM'][] = $name;
    }
    return $this;
  }

  public function join($table, $cond, $type = 'INNER')
  {
    static $types = array(
      'inner' => 'INNER JOIN',
      'left'  => 'LEFT JOIN',
      'right' => 'RIGHT JOIN',
      'full'  => 'FULL JOIN',
    );
    $type = strtolower($type);

    if (strpos($cond, '=')) {
      $cond = 'ON ' . $cond;
    } else {
      $cond = 'USING (' . $cond . ')';
    }

    if (!is_array($table)) {
      $table = array($table);
    }
    foreach ($table as $alias => $name) {
      if (!is_int($alias)) {
        $name .= ' AS ' . $alias;
      }
      $this->_activeRec['JOIN'][] = $types[$type] . ' ' . $name . ' ' . $cond;
    }
    return $this;
  }

  public function limit($limit, $offset = null)
  {
    $this->_activeRec['LIMIT'] = $limit;
    $this->_activeRec['OFFSET'] = $offset;
    return $this;
  }

  public function limitPage($limit, $page = 1)
  {
    $offset = $limit * ($page - 1);
    $this->limit($limit, $offset);
    return $this;
  }

  public function where($cond, $value, $type = 'AND', $escape = true, $recKey = 'WHERE')
  {
    static $types = array(
      'and' => 'AND',
      'or'  => 'OR',
    );
    $type = strtolower($type);

    static $ops = array('>=', '<=', '<>', '!=', '=', '>', '<', 'IN', 'LIKE');
    $cond = trim($cond);
    if (false !== ($eqPos = strpos($cond, ' '))) {
      $field = trim(substr($cond, 0, $eqPos));
      $op = strtoupper(trim(substr($cond, $eqPos + 1)));
      if (!in_array($op, $ops)) {
        $op = '=';
      }
    } else {
      $field = $cond;
      $op = '=';
    }
    if ($op == 'IN') {
      if (is_array($value)) {
        foreach ($value as &$v) {
          $v = '"' . $this->_proxyInstance->escape($v) . '"';
        }
        $value = '(' . implode(', ', $value) . ')';
      } else {
        $op = '=';
        $value = '"' . $this->_proxyInstance->escape($value) . '"';
      }
    } else {
      if ($escape) {
        $value = '"' . $this->_proxyInstance->escape($value) . '"';
      }
    }
    $this->_activeRec[$recKey][] = array(
      'field' => $field,
      'op'    => $op,
      'type'  => $types[$type],
      'value' => $value,
    );
    return $this;
  }

  public function having($cond, $value, $type = 'AND', $escape = true)
  {
    return $this->where($cond, $value, $type, $escape, 'HAVING');
  }

  public function orderby($order)
  {
    $order = explode(',', $order);
    foreach ($order as $field) {
      $this->_activeRec['ORDERBY'][] = trim($field);
    }
    return $this;
  }

  public function groupby($group)
  {
    $group = explode(',', $group);
    foreach ($group as $field) {
      $this->_activeRec['GROUPBY'][] = trim($field);
    }
    return $this;
  }

  public function getSql($table = null, $limit = null, $offset = null)
  {
    if (isset($table)) {
      $this->from($table);
    }
    if (isset($limit)) {
      $this->limit($limit, $offset);
    }
    $sql = $this->_compileSelect();
    $this->_resetSelect();
    return $sql;
  }

  public function __toString()
  {
    return $this->getSql();
  }

  public function query()
  {
    return $this->_proxyInstance->query($this->getSql());
  }

  private function _compileWhere($recKey = 'WHERE')
  {
    $sql = '';
    if ($recKey == 'WHERE' || $recKey == 'HAVING') {
      $rec = $this->_activeRec;
      if (isset($rec[$recKey][0])) {
        $sql .= ' ' . $recKey;
        foreach ($rec[$recKey] as $num => $cond) {
          if ($num > 0){
            $sql .= ' ' . $cond['type'];
          }
          if (false === strpos($cond['field'], '.')) {
            $sql .= ' `' . $cond['field'] . '`';
          } else {
            $sql .= ' ' . $cond['field'];
          }
          $sql .=  ' ' . $cond['op'] . ' ' . $cond['value'];
        }
      }
    }
    return $sql;
  }

  private function _compileSelect()
  {
    $sql = 'SELECT';
    $rec = $this->_activeRec;
    if ($rec['DISTINCT']) {
      $sql .= ' DISTINCT';
    }
    if (isset($rec['SELECT'][0])) {
      $sql .= ' ' . implode(', ', $rec['SELECT']);
    } else {
      $sql .= ' *';
    }
    if (isset($rec['FROM'][0])) {
      $sql .= ' FROM ' . implode(', ', $rec['FROM']);
    }
    if (isset($rec['JOIN'][0])) {
      $sql .= ' ' . implode(' ', $rec['JOIN']);
    }
    $sql .= $this->_compileWhere('WHERE');
    if (isset($rec['GROUPBY'][0])) {
      $sql .= ' GROUP BY ' . implode(', ', $rec['GROUPBY']);
    }
    if (isset($rec['ORDERBY'][0])) {
      $sql .= ' ORDER BY ' . implode(', ', $rec['ORDERBY']);
    }
    $sql .= $this->_compileWhere('HAVING');
    if (isset($rec['LIMIT'])) {
      $sql .= ' LIMIT ' . (isset($rec['OFFSET']) && $rec['OFFSET'] > 0 ? ($rec['OFFSET'] . ', ') : '') . $rec['LIMIT'];
    }
    return $sql;
  }
}

final class BpfQueryResult
{
  private $_result;
  private $_sql;

  public function __construct($sql, $result)
  {
    $this->_sql = $sql;
    $this->_result = $result->result;
  }

  public function getSql()
  {
    return $this->_sql;
  }

  public function all()
  {
    return $this->_result;
  }

  public function allWithKey($key)
  {
    if (!is_array($this->_result)) {
      return $this->_result;
    }
    $result = array();
    foreach ($this->_result as $row) {
      if (!isset($row->{$key})) {
        return false;
      }
      $result[$row->{$key}] = $row;
    }
    return $result;
  }

  public function column($index = 0)
  {
    if (!is_array($this->_result)) {
      return $this->_result;
    }
    $result = array();
    $columnName = null;
    foreach ($this->_result as $row) {
      if (!isset($columnName)) {
        $fields = array_keys((array) $row);
        if (is_int($index) && isset($fields[$index])) {
          $columnName = $fields[$index];
        } else if (in_array($index, $fields)) {
          $columnName = $index;
        } else {
          return false;
        }
      }
      $result[] = $row->{$columnName};
    }
    return $result;
  }

  public function columnWithKey($key, $index = 0)
  {
    if (!is_array($this->_result)) {
      return $this->_result;
    }
    $result = array();
    $columnName = null;
    foreach ($this->_result as $row) {
      if (!isset($row->{$key})) {
        return false;
      }
      if (!isset($columnName)) {
        $fields = array_keys((array) $row);
        if (is_int($index) && isset($fields[$index])) {
          $columnName = $fields[$index];
        } else if (in_array($index, $fields)) {
          $columnName = $index;
        } else {
          return false;
        }
      }
      $result[$row->{$key}] = $row->{$columnName};
    }
    return $result;
  }

  public function row()
  {
    if (!is_array($this->_result)) {
      return $this->_result;
    }
    return reset($this->_result);
  }

  public function field($index = 0)
  {
    if (!is_array($this->_result)) {
      return $this->_result;
    }
    $row = reset($this->_result);
    if ($row) {
      $fields = array_keys((array) $row);
      if (is_int($index) && isset($fields[$index])) {
        $columnName = $fields[$index];
      } else if (in_array($index, $fields)) {
        $columnName = $index;
      } else {
        return false;
      }
      return $row->{$columnName};
    }
    return false;
  }
}

final class BpfExecuteResult
{
  private $_result;
  private $_sql;

  public function __construct($sql, $result)
  {
    $this->_sql = $sql;
    $this->_result = $result;
  }

  public function getSql()
  {
    return $this->_sql;
  }

  public function affected()
  {
    if (!is_object($this->_result)) {
      return $this->_result;
    }
    return $this->_result->affectedRows;
  }

  public function insertId()
  {
    if (!is_object($this->_result)) {
      return $this->_result;
    }
    return $this->_result->insertId;
  }
}
