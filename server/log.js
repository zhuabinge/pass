var fs = require('fs');
var Log = {
  INFO: 'INFO',
  NOTICE: 'NOTICE',
  WARNING: 'WARNING',
  ERROR: 'ERROR',
  FATAL: 'FATAL',
  loggers: {},
  log: function(logger, type, message, output) {
    if (Log.loggers[logger]) {
      var filename = Log.loggers[logger];
      fs.writeFileSync(filename, Log.format(type, message), {flag: 'a'});
    }
    if (output || false) {
      console.log(message);
    }
  },
  format: function(type, message) {
    var pad2 = function(num) {
      return num < 10 ? ('0' + num) : num;
    };
    var pad3 = function(num) {
      return num < 10 ? ('00' + num) : (num < 100 ? ('0' + num) : num);
    };
    var t = new Date();
    return [
      '[', t.getFullYear(), '-', pad2(t.getMonth() + 1), '-', pad2(t.getDate()), ' ',
      pad2(t.getHours()), ':', pad2(t.getMinutes()), ':', pad2(t.getSeconds()), '.',
      pad3(t.getMilliseconds()), '] [', type, '] ', message, "\n"
    ].join('');
  },
  getLogger: function(logger) {
    return {
      info: function(message, output) { Log.log(logger, Log.INFO, message, output); },
      notice: function(message, output) { Log.log(logger, Log.NOTICE, message, output); },
      warning: function(message, output) { Log.log(logger, Log.WARNING, message, output); },
      error: function(message, output) { Log.log(logger, Log.ERROR, message, output); },
      fatal: function(message, output) { Log.log(logger, Log.FATAL, message, output); }
    };
  },
  setLogger: function(logger, filename) {
    Log.loggers[logger] = filename;
  }
};

exports.getLogger = Log.getLogger;
exports.setLogger = Log.setLogger;
