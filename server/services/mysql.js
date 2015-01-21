var mysql = {
  connection: null,
  timer: null,
  config: null,
  log: null,
  assert: function(error) {
    if (error) {
      mysql.log.getLogger('mysql-error').error(error);
      throw '[mysql] ' + error;
    }
  },
  init: function(config) {
    var client = require('mysql-libmysqlclient'), result;
    var connection;
    config.log_query = parseInt(config.log_query, 10) || false;
    mysql.config = config;
    var log = mysql.log = require('../log');
    log.setLogger('mysql-error', config.log_path + '/mysql.log');
    log.setLogger('mysql-query', config.log_path + '/mysql.query.log');
    mysql.connection = connection = client.createConnectionSync();
    connection.connectSync(
      config.host || '127.0.0.1',
      config.user || 'root',
      config.password || '',
      config.name || '',
      config.port || 3306
    );
    if (!connection.connectedSync()) {
      throw '数据库连接失败: ' + connection.connectErrno + ': ' + connection.connectError;
    }
    connection.setCharsetSync('UTF8');
    mysql.format = require('../bodao').sqlString.format;
    mysql.timer = setInterval(function() {
      connection.pingSync();
    }, 60000);
  },
  uninit: function() {
    if (mysql.connection && mysql.connection.connectedSync()) {
      mysql.connection.closeSync();
    }
    if (mysql.timer) {
      clearTimeout(mysql.timer);
    }
  },
  query: function(sql) {
    var conn = mysql.connection, timeStart = new Date().getTime();
    try {
      var result, timeDiff, rows;
      result = conn.querySync(sql);
      if (result) {
        rows = result.fetchAllSync();
        result.freeSync();
      } else {
        throw conn.errorSync();
      }
      timeDiff = new Date().getTime() - timeStart;
      if (mysql.config.log_query) {
        mysql.log.getLogger('mysql-query').info('查询 SQL (' +
            timeDiff.toString() + ' ms) [' + sql + '] (' +
            timeDiff.toString() + ' ms)');
      }
      return rows;
    } catch (error) {
      mysql.log.getLogger('mysql-error').error('查询错误 [' + error + '] SQL [' + sql + ']');
      return false;
    }
  },
  post_query: function(req, res) {
    var postData = '', post;
    req.on('data', function(chunk) {
      postData += chunk;
    });
    req.on('end', function() {
      post = require('querystring').parse(postData);
      if (post.sql === undefined) {
        throw 'Query is wrong.';
      }
      var conn = mysql.connection, timeStart = new Date().getTime();
      try {
        var result, timeDiff, rows;
        result = conn.querySync(post.sql);
        if (result) {
          rows = result.fetchAllSync();
          result.freeSync();
        } else {
          throw conn.errorSync();
        }
        timeDiff = new Date().getTime() - timeStart;
        res.send({
          result: rows
        });
        if (mysql.config.log_query) {
          mysql.log.getLogger('mysql-query').info('查询 SQL (' +
              timeDiff.toString() + ' ms) [' + post.sql + '] (' +
              timeDiff.toString() + ' ms)');
        }
      } catch (error) {
        res.send(503, {
          error: error
        });
        mysql.log.getLogger('mysql-error').error('查询错误 [' + error + '] SQL [' + post.sql + ']');
      }
    });
  },
  execute: function(sql) {
    var conn = mysql.connection, timeStart = new Date().getTime();
    try {
      var result, timeDiff;
      result = conn.querySync(sql);
      if (!result) {
        throw conn.errorSync();
      }
      timeDiff = new Date().getTime() - timeStart;
      if (mysql.config.log_query) {
        mysql.log.getLogger('mysql-query').
            info('执行 SQL (' + timeDiff.toString() + ' ms) [' + sql +
            '] (' + timeDiff.toString() + ' ms)');
      }
      return {
        affectedRows: conn.affectedRowsSync(),
        insertId: conn.lastInsertIdSync()
      };
    } catch (error) {
      mysql.log.getLogger('mysql-error').error('执行错误 [' + error + '] SQL [' + sql + ']');
      return false;
    }
  },
  post_execute: function(req, res) {
    var postData = '', post;
    req.on('data', function(chunk) {
      postData += chunk;
    });
    req.on('end', function() {
      post = require('querystring').parse(postData);
      if (post.sql === undefined) {
        throw 'Query is wrong.';
      }
      var conn = mysql.connection, timeStart = new Date().getTime();
      try {
        var result, timeDiff;
        result = conn.querySync(post.sql);
        if (!result) {
          throw conn.errorSync();
        }
        timeDiff = new Date().getTime() - timeStart;
        res.send({
          affectedRows: conn.affectedRowsSync(),
          insertId: conn.lastInsertIdSync()
        });
        if (mysql.config.log_query) {
          mysql.log.getLogger('mysql-query').
              info('执行 SQL (' + timeDiff.toString() + ' ms) [' + post.sql +
              '] (' + timeDiff.toString() + ' ms)');
        }
      } catch (error) {
        res.send(503, {
          error: error
        });
        mysql.log.getLogger('mysql-error').error('执行错误 [' + error + '] SQL [' + post.sql + ']');
      }
    });
  }
};

module.exports = mysql;
