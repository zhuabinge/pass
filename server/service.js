#!/usr/bin/node

var cluster = require('cluster'), log = require('./log'), fs = require('fs'),
   mysql = require('mysql-libmysqlclient'), util = require('util');
var isMaster = cluster.isMaster, workerProcesses = 0, daemonize = false;
var config = require('./config.js');

// 退出函数
var onExit = function() {
  process.exit(1);
};
process.on('SIGTERM', onExit);
process.on('SIGINT', onExit);
// 错误函数
var onError = function(error) {
  log.getLogger('bodao').fatal(require('util').format(error.stack), true);
  if (isMaster) {
    log.getLogger('bodao').fatal('服务进程异常', daemonize ? false : true);
  }
  process.exit(1);
};
process.on('uncaughtException', function(error) {
  log.getLogger('bodao').fatal(require('util').format(error.stack));
  onError(error);
});

do {
  var argv = process.argv, op = 'start';
  if (argv.length == 3) {
    op = argv[2];
  }
  if (op !== 'start' && op !== 'stop' && op !== 'restart') {
    console.log('无效的启动参数');
    break;
  }
  daemonize = config.server.daemonize || false;
  // 创建日志
  var logPath = fs.realpathSync(__dirname + '/logs');
  log.setLogger('bodao', logPath + '/server.log');
  // 检查服务配置
  if (config.service === undefined || !util.isArray(config.service) || !config.service.length) {
    if (isMaster) {
      log.getLogger('bodao').fatal('没有配置任何服务', true);
      log.getLogger('bodao').fatal('服务进程异常', true);
    }
    break;
  }
  if (isMaster) { // 主进程
    // 产生 pid
    var pid = __dirname + '/service.pid', removePid = false;
    if (op === 'stop' || op === 'restart') {
      if (!fs.existsSync(pid)) {
        console.log('找不到已启动的服务进程');
        break;
      } else {
        var processPid = parseInt(fs.readFileSync(pid, 'ascii'), 10);
        if (!isNaN(processPid)) {
          process.kill(processPid);
        }
      }
      if (op === 'stop') {
        break;
      } else {
        // 等待 pid 文件删除
        while (fs.existsSync(pid)) {}
      }
    }
    if (fs.existsSync(pid)) {
      log.getLogger('bodao').notice('服务进程已存在', true);
      break;
    }
    if (daemonize) {
      // 后台运行
      if (process.env.__daemonize === undefined) {
        process.env.__daemonize = true;
        var child = require('child_process').spawn(argv[1], [], {
          stdio: [0, 1, 2],
          cwd: process.cwd,
          env: process.env,
          detached: true
        });
        child.unref();
        // 后台进程已启动，主进程关闭
        process.exit(1);
        break;
      }
    }
    // 主进程后台进程
    fs.writeFileSync(pid, process.pid, 'ascii');
    removePid = true;
    process.on('exit', function() {
      if (removePid && fs.existsSync(pid)) {
        fs.unlinkSync(pid);
      }
      log.getLogger('bodao').info('服务进程已终止', daemonize ? false : true);
    });
    // 启动子进程
    if (config.server.worker_processes !== undefined) {
      workerProcesses = Math.max(Math.min(parseInt(config.server.worker_processes, 10), 32), 1);
    } else {
      workerProcesses = require('os').cpus().length;
    }
    var workers = [];
    for (var i = 0; i < workerProcesses; ++i) {
      workers.push(cluster.fork());
    }
    log.getLogger('bodao').info('服务进程已启动, 子进程数 ' + workerProcesses, daemonize ? false : true);
  } else {  // 子进程
    var services = {};
    process.on('exit', function() {
      // 服务卸载函数
      var service;
      for (var i in services) {
        service = services[i];
        if (typeof service.uninit === 'function') {
          service.uninit();
        }
      }
      services = {};
    });

    exports.getService = function(service) {
      return services[service] !== undefined ? services[service] : false;
    };

    // 加载服务文件
    var domainLoad = require('domain').create();
    domainLoad.on('error', function(error) {
      log.getLogger('bodao').fatal(error);
      log.getLogger('bodao').fatal('子进程异常终止', true);
      process.exit(1);
    });
    domainLoad.run(function() {
      var loaded = true, service, serviceName;
      for (var i in config.service) {
        serviceName = config.service[i];
        try {
          service = require('./services/' + serviceName);
          if (typeof service.init === 'function') {
            var conf = config[serviceName] || {};
            conf.log_path = logPath;
            service.init(conf);
          }
          services[serviceName] = service;
        } catch (error) {
          log.getLogger('bodao').fatal('[' + serviceName + '] ' + error);
          loaded = false;
          break;
        }
      }
      if (!loaded) {
        log.getLogger('bodao').fatal('子进程异常终止', true);
        process.exit(1);
      }
    });

    // 启动 REST 服务器
    var domainRest = require('domain').create();
    domainRest.on('error', onError);
    domainRest.run(function() {
      var hostname = config.server.hostname || null, port = config.server.port || 8080;
      var server = require('restify').createServer();
      log.setLogger('rest-error', logPath + '/restful.error.log');
      var funcRespond = function(req, res) {
        var service = req.params.service, method = req.method.toLowerCase() + '_' + req.params.method,
            headers = req.headers, instance;
        do {
          if (headers.token === undefined || headers.token !== config.server.token) {
            res.send(403, { error: '该服务无权访问' });
            break;
          }
          if (services[service] === undefined || ((instance = services[service]) &&
              typeof instance[method] !== 'function')) {
            res.send(404, { error: '服务名称无效' });
            break;
          }
          try {
            instance[method](req, res);
            return;
          } catch (e) {
            res.send(500, { error: e.toString() });
            break;
          }
        } while (0);
      };
      server.get(':service/:method', funcRespond);
      server.post(':service/:method', funcRespond);
      server.put(':service/:method', funcRespond);
      server.del(':service/:method', funcRespond);
      server.listen(port, hostname, function() {
        log.getLogger('bodao').info('[rest] 服务启动成功, 地址: ' + server.url);
      });
      server.on('error', function(error) {
        log.getLogger('oa').fatal('[rest] ' + error);
        log.getLogger('oa').fatal('子进程异常终止', true);
        process.exit(1);
      });
      server.on('uncaughtException', function(req, res, route, err) {
        log.getLogger('rest-error').error('[' + req.method + ':' + req.url + '] ' + err);
        try {
          res.send(500, { error: err.toString() });
        } catch (e) {}
      });
    });
  }
} while (0);
