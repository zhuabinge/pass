var cache = {
  redis: null,
  client: null,
  config: null,
  log: null,
  assert: function(error) {
    if (error) {
      cache.log.getLogger('cache').error(error);
      throw '[cache] ' + error;
    }
  },
  init: function(config) {
    config.expires = config.expires || 1800;
    cache.config = config;
    var log = cache.log = require('../log');
    log.setLogger('cache', config.log_path + '/cache.log');
    var redis = cache.redis = require('redis');
    var client = cache.client = redis.createClient(
        config.port || 6379,
        config.hostname || '127.0.0.1'
    );
    client.on('error', cache.assert);
  },
  uninit: function() {
    cache.client.quit();
  },
  get: function(key, callback) {
    if (typeof callback === 'function') {
      cache.client.get(key, function(error, value) {
        cache.assert(error);
        callback(value);
      });
    }
  },
  get_value: function(req, res) {
    var query = require('url').parse(req.url, true).query;
    if (query.key === undefined) {
      throw 'Query is wrong.';
    }
    var key = query.key;
    cache.client.get(key, function(error, value) {
      cache.assert(error);
      res.send({value: value});
    });
  },
  set: function(key, value, ex) {
    if (ex === undefined) {
      ex = cache.config.expires;
    }
    if (ex > 0) {
      cache.client.setex(key, ex, value, function(error) {
        cache.assert(error);
      });
    } else {
      cache.client.set(key, value, function(error) {
        cache.assert(error);
      });
    }
  },
  put_value: function(req, res) {
    var query = require('url').parse(req.url, true).query;
    if (query.key === undefined) {
      throw 'Query is wrong.';
    }
    var key = query.key, postData = '', post;
    req.on('data', function(chunk) {
      postData += chunk;
    });
    req.on('end', function() {
      post = require('querystring').parse(postData);
      if (post.value === undefined) {
        throw 'Query is wrong.';
      }
      if (post.ex === undefined) {
        post.ex = cache.config.expires;
      }
      if (post.ex > 0) {
        cache.client.setex(key, post.ex, post.value, function(error) {
          cache.assert(error);
          res.send({affected: 1});
        });
      } else {
        cache.client.set(key, post.value, function(error) {
          cache.assert(error);
          res.send({affected: 1});
        });
      }
    });
  },
  del: function(key) {
    if (typeof key === 'string') {
      cache.client.keys(key, function(error, value) {
        cache.assert(error);
        if (value.length) {
          cache.client.del(value, function(error, value) {
            cache.assert(error);
          });
        }
      });
    } else {
      if (key.length) {
        cache.client.del(key, function(error, value) {
          cache.assert(error);
        });
      }
    }
  },
  delete_value: function(req, res) {
    var query = require('url').parse(req.url, true).query;
    if (query.key === undefined) {
      throw 'Query is wrong.';
    }
    var key = query.key;
    if (typeof key === 'string') {
      cache.client.keys(key, function(error, value) {
        cache.assert(error);
        if (value.length) {
          cache.client.del(value, function(error, value) {
            cache.assert(error);
            res.send({affected: value});
          });
        } else {
          res.send({affected: 0});
        }
      });
    } else {
      if (key.length) {
        cache.client.del(key, function(error, value) {
          cache.assert(error);
          res.send({affected: value});
        });
      } else {
        res.send({affected: 0});
      }
    }
  },
  get_keys: function(req, res) {
    var query = require('url').parse(req.url, true).query;
    if (query.key === undefined) {
      throw 'Query is wrong.';
    }
    var key = query.key;
    cache.client.keys(key, function(error, value) {
      cache.assert(error);
      res.send({keys: value});
    });
  }
};

module.exports = cache;
