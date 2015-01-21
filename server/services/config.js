var fs = require('fs');
var config = {
  db: null,
  log: null,
  config: {},
  assert: function(error) {
    if (error) {
      config.log.getLogger('config').error(error);
      throw '[config] ' + error;
    }
  },
  init: function(conf) {
    var log = config.log = require('../log');
    log.setLogger('config', conf.log_path + '/config.log');
    config.db = require('../service').getService('mysql');
  },
  uninit: function() {
  },
  put_createInterfaceConfig: function(req, res) {
    var db = config.db;
    try {
      var cfg = db.query('SELECT * FROM `main_config`');
      var cfg_inter = db.query('select inter1.name,inp.*,outp.out_num,inter2.name name2 from `interface` inter1 inner join `inpackage` inp inner join `interface` inter2 inner join `outpackage` outp on inter1.inter_id=inp.inter_id and inter2.inter_id=inp.inter_id2 and inter2.inter_id=outp.inter_id');
      //console.log(cfg_inter);
      if (!cfg || !cfg[0] || !cfg_inter || !cfg_inter[0]) {
        throw '找不到配置';
      }
      cfg = cfg[0];

      /**
      *配置全局Head
      */
      if (cfg.max_send_size_type == 1) {
        cfg.max_send_size_type = 'K';
      } else if (cfg.max_send_size_type == 2) {
        cfg.max_send_size_type = 'M';
      }
      var cfg_head = 'max_dns_pkt_size ' + cfg.max_dns_pkt_size + '\n' +
      'max_http_pkt_size ' + cfg.max_http_pkt_size + '\n' +
      'max_send_size ' + cfg.max_send_size + cfg.max_send_size_type + '\n' +
      'max_log_len ' + cfg.max_log_len + '\n' +
      'watermask ' + cfg.watermask + '\n' ;

      /**
      *配置http_method
      */
      var cfg_http_method = '<spo_hp_method>\n';
      var http = [
      'OPTIONS',
      'HEAD',
      'GET',
      'POST',
      'PUT',
      'DELETE',
      'TRACE',
      'CONNECT',
      'PATCH'
      ];
      for (var i = 0; i < 9; i++) {
        if (cfg.http_method[i] == i +1) {
          cfg_http_method += '\thttp_method ' + http[i] + '\n';
        }
      }
      cfg_http_method += '</spo_hp_method>\n\n';

      /**
      *配置sinffers
      */
      var seed = Math.ceil(Math.random()*9) + 100000;
      var cfg_sniffers = '';
      var http_msgid_arr = [];  //存放http_msgid的数组
      var dns_msgid_arr = [];  //存放dns_msgid的数组
      var http_num = [];  //存放当前http中进程个数的数组
      var dns_num = [];  //存放当前dns中进程个数的数组
      var tcp = [];  //存放既有tcp又有udp时tcp当前的msgid的位置的数组
      var udp = [];  //存放既有tcp又有udp时udp当前的msgid的位置的数组
      var tcp_inter = [];  //存放属于tcp的cfg_inter的下标的数组
      var udp_inter = [];  //存放属于udp的cfg_inter的下标的数组
      var tcp_udp_inter = []; //存放既有tcp又有udp时cfg_inter的下标的数组

      for (var i = 0; i < cfg_inter.length; i++) {
        var http_msgid = '';
        var dns_msgid = '';
        var snd_msgid = '';
        var filter = '\n';
        if (cfg_inter[i].type1 == '10') {
          filter += '\tfilter tcp\n';
          tcp_inter.push(i);
          http_num.push(cfg_inter[i].out_num);
          for (var j = 0; j < cfg.http_spoofers; j++) {
           http_msgid_arr.push(seed);
           http_msgid += '\thttp_msgid ' + seed++ + '\n';
         }
       } else if (cfg_inter[i].type1 == '02') {
        filter += '\tfilter udp\n';
        udp_inter.push(i);
        dns_num.push(cfg_inter[i].out_num);
        for (var j = 0; j < cfg.dns_spoofers; j++) {
          dns_msgid_arr.push(seed);
          dns_msgid += '\tdns_msgid ' + seed++ + '\n';
        }
      } else if (cfg_inter[i].type1 == '12') {
        filter += '\tfilter tcp or udp\n';
        tcp_inter.push(i);
        tcp_udp_inter.push(i);
        tcp.push(http_num.length);
        udp.push(dns_num.length);
        http_num.push(cfg_inter[i].out_num);
        dns_num.push(cfg_inter[i].out_num);
        for (var j = 0; j < cfg.http_spoofers; j++) {
          http_msgid_arr.push(seed);
          http_msgid += '\thttp_msgid ' + seed++ + '\n';
        }
        for (var j = 0; j < cfg.dns_spoofers; j++) {
          dns_msgid_arr.push(seed);
          dns_msgid += '\tdns_msgid ' + seed++ + '\n';
        }
      }
      var useing_lib = '\t';
      if (cfg_inter[i].type2 == 1) {
        useing_lib += 'useing_lib pcap\n';
      } else if (cfg_inter[i].type2 == 2) {
        if (cfg_inter[i].type3 == '10') {
          useing_lib += 'useing_lib pf\n\tdata_direc rx\n';
        } else if (cfg_inter[i].type3 == '02') {
          useing_lib += 'useing_lib pf\n\tdata_direc tx\n';
        }
      }
      cfg_sniffers += '<spo_sniffer>\n\tdev_r ' + cfg_inter[i].name + filter + useing_lib + '\tanalysiser ' + cfg_inter[i].analysiser + '\n' + http_msgid + dns_msgid + '\tproc_type sniffer\n\tcpuid 1\n</spo_sniffer>\n\n';
    }

      /**
      *配置http_spoofers
      */
      var http_snd_msgid_arr = [];
      var tcp_arr = [];
      var http_spoofer = '';
      for (var i = 0; i < http_num.length; i++) {
        var http_snd_msgid = '';
        for (var j = 0; j < http_num[i]; j++) {
          for (var k = 0; k < tcp.length; k++){
            if (i == tcp[k]) {
              tcp_arr.push(http_snd_msgid_arr.length);
              break;
            }
          }
          http_snd_msgid_arr.push(seed);
          http_snd_msgid += '\n\tsnd_msgid ' + seed++ ;
        }
        for (var k = 0; k < cfg.http_spoofers; k++) {
          http_spoofer += '<spo_http_spoofer>\n\trcv_msgid ' + http_msgid_arr[cfg.http_spoofers * i +k] + http_snd_msgid + '\n\tproc_type http_spoofer\n\tcpuid 3\n</spo_spoofer>\n\n';
        }
      }

      /**
      *配置dns_spoofers
      */
      var dns_snd_msgid_arr = [];
      var udp_arr = [];
      var dns_spoofer = '';
      for (var i = 0; i < dns_num.length; i++) {
        var dns_snd_msgid = '';
        var type = false;
        for(var j = 0; j< dns_num[i]; j++) {
          var flag = false;
          for (var k = 0; k < udp.length; k++){
            if (i == udp[k]) {
              udp_arr.push(dns_snd_msgid_arr.length);
              flag = true;
              type = true;
              break;
            }
          }
          if (!flag) {
            dns_snd_msgid_arr.push(seed);
            dns_snd_msgid += '\n\tsnd_msgid ' + seed++ ;
          }
        }
        if (!type) {
          for (var k = 0; k < cfg.dns_spoofers; k++) {
            dns_spoofer += '<spo_dns_spoofer>\n\trcv_msgid ' + dns_msgid_arr[cfg.dns_spoofers * i +k] + dns_snd_msgid + '\n\tproc_type dns_spoofer\n\tcpuid 3\n</spo_spoofer>\n\n';
          }
        }
      }
      for (var i = 0; i < tcp.length; i++) {
        var dns_snd_msgid = '';
        for (var j = 0; j < http_num[tcp[i]]; j++) {
          dns_snd_msgid += '\n\tsnd_msgid ' + http_snd_msgid_arr[tcp_arr[i + j]];
        }
        for (var k = 0; k < cfg.dns_spoofers; k++) {
          dns_spoofer += '<spo_dns_spoofer>\n\trcv_msgid ' + dns_msgid_arr[udp_arr[i + k]] + dns_snd_msgid + '\n\tproc_type dns_spoofer\n\tcpuid 3\n</spo_spoofer>\n\n';
        }
      }
      /**
      *配置spo_sender
      */
      var spo_sender = '';
      var location = 0;
      for (var i = 0; i < tcp_inter.length; i++) {
        for (var j = 0; j < http_num[i]; j++) {
          spo_sender += '<spo_sender>\n\tdev_s ' + cfg_inter[tcp_inter[i]].name2 + '\n\trcv_msgid ' + http_snd_msgid_arr[location] + '\n\tcpuid 3\n\tproc_type sender\n</spo_sender>\n\n';
          location++;
        }
      }
      var location = 0;
      for (var i = 0; i < udp_inter.length; i++) {
        for (var j = 0; j < dns_num[i]; j++) {
          spo_sender += '<spo_sender>\n\tdev_s ' + cfg_inter[udp_inter[i]].name2 + '\n\trcv_msgid ' + dns_snd_msgid_arr[location] + '\n\tcpuid 3\n\tproc_type sender\n</spo_sender>\n\n';
          location++;
        }
      }
      if (fs.existsSync('/NoGFW/bin/config')) {
        fs.unlinkSync('/NoGFW/bin/config');
      }
      fs.appendFileSync('/NoGFW/bin/config', cfg_head + '\n\n' + cfg_http_method + cfg_sniffers + http_spoofer + dns_spoofer + spo_sender);
      res.send({
        success: true,
      });
    } catch (e) {
      res.send({
        success: false,
        msg: e
      });
    }
  },

  put_createHttpDataConfig: function(req, res) {
    var db = config.db;
    var cfg = db.query('SELECT data.*,domain.domain FROM `http_data` data inner join `http_domain` domain on data.do_id=domain.do_id');
    try {
      if (!cfg || !cfg[0]) {
        throw '找不到配置';
      }
      for (i = 0; i < cfg.length; i++) {
        var filename = cfg[i].data_num + '@' + cfg[i].domain;
        if (fs.existsSync('/NoGFW/bin/http/' + filename)) {
          fs.unlinkSync('/NoGFW/bin/http/' + filename);
        }
        fs.appendFileSync('/NoGFW/bin/http/' + filename, cfg[i].head + '\n\n' + cfg[i].body);
      }
      res.send({success: true});
    } catch (e) {
      res.send({
        success: false,
        msg: e
      });
    }
  },
  put_createHttpRuleConfig: function(req, res) {
    var db = config.db;
    var cfg = db.query('SELECT do.domain,rule.* FROM `http_domain` do inner join `http_rule` rule on do.do_id=rule.do_id order by do.domain,rule.orders');
    try {
      if (!cfg || !cfg[0]) {
        throw '找不到配置';
      }
      var rule = '';
      for (var i = 0; i < cfg.length; i++) {
        if ( i == 0) {
          rule += '<spo_domain ' + cfg[i].domain + '>';
        } else if ( i > 0 ){
          if (cfg[i].domain != cfg[i - 1].domain) {
            rule += '\n</spo_domain>\n\n<spo_domain ' + cfg[i].domain + '>';
          }
        }
        rule += '\n\turl: ' + cfg[i].url + ',,,cookies: ' + cfg[i].cookies + ',,,referer: ' + cfg[i].referer + ',,,@' + cfg[i].data_num;
      }
      rule += '\n</spo_domain>';
      if (fs.existsSync('/NoGFW/bin/http.config')) {
        fs.unlinkSync('/NoGFW/bin/http.config');
      }
      fs.writeFileSync('/NoGFW/bin/http.config', rule);
      res.send({
        success: true,
      });
    } catch (e) {
      res.send({
        success: false,
        msg: e
      });
    }
  }
};

module.exports = config;
