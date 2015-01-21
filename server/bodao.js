var Bodao = {
  sqlString: {
    format: function(sql, values) {
      values = [].concat(values);
      return sql.replace(/\?/g, function(match) {
        if (!values.length) {
          return match;
        }
        return Bodao.sqlString.escape(values.shift(), false);
      });
    },
    escape: function(val, stringifyObjects) {
      var sqlString = Bodao.sqlString;
      if (val === undefined || val === null) {
        return 'NULL';
      }
      switch (typeof val) {
        case 'boolean':
          return (val) ? 'true' : 'false';
        case 'number':
          return val + '';
      }
      if (Array.isArray(val)) {
        return sqlString.arrayToList(val);
      }
      if (typeof val === 'object') {
        if (stringifyObjects) {
          val = val.toString();
        } else {
          return sqlString.objectToValues(val);
        }
      }
      val = val.replace(/[\0\n\r\b\t\\\'\"\x1a]/g, function(s) {
        switch(s) {
          case "\0": return "\\0";
          case "\n": return "\\n";
          case "\r": return "\\r";
          case "\b": return "\\b";
          case "\t": return "\\t";
          case "\x1a": return "\\Z";
          default: return "\\"+s;
        }
      });
      return "'" + val + "'";
    },
    arrayToList: function(array) {
      var sqlString = Bodao.sqlString;
      return array.map(function(v) {
        if (Array.isArray(v)) return '(' + sqlString.arrayToList(v) + ')';
        return sqlString.escape(v, true);
      }).join(', ');
    },
    objectToValues: function(object) {
      var values = [], sqlString = Bodao.sqlString, key;
      for (key in object) {
        var value = object[key];
        if(typeof value === 'function') {
          continue;
        }
        values.push('`' + key + '` = ' + sqlString.escape(value, true));
      }
      return values.join(', ');
    }
  },
  randomString: function(len, type) {
    var randstring = '1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ', result = [], length, i;
    if (type !== undefined) {
      if (type === 10 || type === 16) {
        randstring.substr(0, type);
      } else if (type === 'a') {
        randstring.substr(10);
      }
    }
    length = randstring.length - 1;
    for (i = 0; i < len; ++i) {
      result.push(randstring.substr(Math.floor(Math.random() * length), 1));
    }
    return result.join('');
  },
  parsePostData: function(req, encoding, callback) {
    var postData = '';
    if (typeof encoding === 'function') {
      callback = encoding;
    } else if (typeof encoding === 'string') {
      req.setEncoding(encoding);
    }
    req.on('data', function(chunk) {
      postData += chunk;
    });
    req.on('end', function() {
      var post = {};
      do {
        var boundary, blocks, matches;
        if (!req.headers['content-type'] || !(boundary = req.headers['content-type'].match(/boundary=(.*)$/))) {
          break;
        }
        boundary = boundary[1];
        blocks = postData.split(new RegExp('-+' + boundary));
        blocks.pop();
        blocks.forEach(function(row) {
          if (row === '' || !(matches = row.match(/name="([^"]+)"[\s\S]*?(?:\r\n){2}([\s\S]*)\r\n$/))) {
            return;
          }
          post[matches[1]] = matches[2];
        });
      } while (0);
      if (typeof callback === 'function') {
        callback(post);
      }
    });
  }
};

module.exports = Bodao;
