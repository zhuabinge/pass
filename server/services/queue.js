var queue = {
  redisClient: null,
  db: null,
  log: null,
  timer: null,
  sysInfos: [],
  assert: function(error) {
    if (error) {
      queue.log.getLogger('queue').error(error);
      throw '[queue] ' + error;
    }
  },
  load: function() {
    if (queue.timer) {
      clearTimeout(queue.timer);
    }
    var sysInfos = queue.sysInfos;
    queue.sysInfos =  [];
    var length =  sysInfos.length,
    infoCount = {
      count: length,
      cpuSum: 0,
      memSum: 0,
      netPortSum: [],
    },
    cpu = 0, mem = 0;
    for (var i = length - 1; i >= 0; i--) {
        infoCount.cpuSum += sysInfos[i]['CPU'];
        infoCount.memSum += sysInfos[i]['Mem'];
        var netPorts = sysInfos[i]['netPort'];
        for (var j = netPorts.length - 1; j >= 0; j--) {
          var netPort = netPorts[j];
          if (!infoCount.netPortSum[netPort[0]]) {
            infoCount.netPortSum[netPort[0]] = {
              upSum: 0,
              downSum: 0,
            };
          }
          var netPortSum = infoCount.netPortSum[netPort[0]];
          netPortSum.upSum += netPort[1];
          netPortSum.downSum += netPort[2];
        }
    }
    console.log(infoCount);
    queue.timer = setTimeout(queue.load, 1000 * 15);  // 每 60 秒重新装载
  },
  init: function(conf) {
    var cache  = queue.redisClient = require('../service').getService('cache');
    var config = cache.config;
    var db = queue.db = require('../service').getService('mysql');
    var log = queue.log = require('../log');
    log.setLogger('queue', conf.log_path + '/queue.log');
    var queueClient =  cache.redis.createClient(
        config.port || 6379,
        config.hostname || '127.0.0.1'
    );
    queueClient.on('error', queue.assert);
    queueClient.on('message', function(channel, message) {
        queue[channel](message);
    });
    queueClient.on('subscribe', function(channel, count) {
      console.log('QUEUE 进程已启动 [' + process.pid + '], 队列: ' + channel + ', 订阅: ' + count);
    });
    conf.forEach(function (queueName) {
      queueClient.subscribe(queueName);
    });
    queue.load();
  },
  uninit: function() {
  },
  sysinfoUpdate: function(message) {
    message = message.split('|');
    var sysInfo = {
      CPU: '',
      Mem: '',
      netPort: [],
      time: parseInt(new Date().getTime() / 1000 , 10) ,
    };
    for (var i = message.length - 1; i >= 0; i--) {
      var info = message[i].split(':');
      if (info[2]) {
        sysInfo.netPort.push([info[0], parseFloat(info[1]), parseFloat(info[2])]);
      } else {
        sysInfo[info[0]] =  parseFloat(info[1]);
      }
    }
    queue.redisClient.set('sysinfoUpdate/' + sysInfo.time, JSON.stringify(sysInfo), 60 * 5);
    queue.sysInfos.push(sysInfo);
  },
};
module.exports = queue;
