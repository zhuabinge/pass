# ************************************************************
# Sequel Pro SQL dump
# Version 4096
#
# http://www.sequelpro.com/
# http://code.google.com/p/sequel-pro/
#
# Host: 127.0.0.1 (MySQL 5.6.21)
# Database: bypass
# Generation Time: 2015-01-08 09:19:35 +0000
# ************************************************************


/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8 */;
/*!40014 SET @OLD_FOREIGN_KEY_CHECKS=@@FOREIGN_KEY_CHECKS, FOREIGN_KEY_CHECKS=0 */;
/*!40101 SET @OLD_SQL_MODE=@@SQL_MODE, SQL_MODE='NO_AUTO_VALUE_ON_ZERO' */;
/*!40111 SET @OLD_SQL_NOTES=@@SQL_NOTES, SQL_NOTES=0 */;


# Dump of table cfg_bus_domains
# ------------------------------------------------------------

DROP TABLE IF EXISTS `cfg_bus_domains`;

CREATE TABLE `cfg_bus_domains` (
  `id` int(11) unsigned NOT NULL AUTO_INCREMENT,
  `domain` varchar(128) NOT NULL DEFAULT '',
  `rules` varchar(255) NOT NULL DEFAULT '',
  `state` tinyint(1) unsigned NOT NULL DEFAULT '0',
  `type` tinyint(2) unsigned NOT NULL DEFAULT '0',
  `created` int(11) unsigned NOT NULL DEFAULT '0',
  `updated` int(11) unsigned NOT NULL DEFAULT '0',
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

LOCK TABLES `cfg_bus_domains` WRITE;
/*!40000 ALTER TABLE `cfg_bus_domains` DISABLE KEYS */;

INSERT INTO `cfg_bus_domains` (`id`, `domain`, `rules`, `state`, `type`, `created`, `updated`)
VALUES
	(1,'www.baidu.com','(1,2)',1,1,0,0),
	(2,'www.qq.com','(3,4,5)',1,1,0,0);

/*!40000 ALTER TABLE `cfg_bus_domains` ENABLE KEYS */;
UNLOCK TABLES;


# Dump of table cfg_bus_rules
# ------------------------------------------------------------

DROP TABLE IF EXISTS `cfg_bus_rules`;

CREATE TABLE `cfg_bus_rules` (
  `id` int(11) unsigned NOT NULL AUTO_INCREMENT,
  `rule` text NOT NULL,
  `addons` text NOT NULL,
  `data` text NOT NULL,
  `state` tinyint(1) NOT NULL DEFAULT '0',
  `created` int(11) unsigned NOT NULL DEFAULT '0',
  `updated` int(11) unsigned NOT NULL DEFAULT '0',
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

LOCK TABLES `cfg_bus_rules` WRITE;
/*!40000 ALTER TABLE `cfg_bus_rules` DISABLE KEYS */;

INSERT INTO `cfg_bus_rules` (`id`, `rule`, `addons`, `data`, `state`, `created`, `updated`)
VALUES
	(1,'url: /.***/?afbc/,,,cookies: /*?.+wd$/,,,referer: /dgle*?.fork1/,,,@5','1212','{addons}\nCookies: BDSVRTM=130; path=/BD_HOME=1; path=/H_PS_PSSID=6255_10162_1432_10624_10572_10490_10213_10501_10496_10510_10647_10052_10459_10065_10218_10687_9392_10356_10666_10096_10658_10442_10403_9950_10688_10627; path=/; domain=.baidu.com\nHost: www.baidu.com\n',1,0,0),
	(2,'url: /.**/?adbc/,,,cookies: /*?.+ws$/,,,referer: /dgel*?.fork5/,,,@6','','Cookies: BDSVRTM=130; path=/BD_HOME=1; path=/H_PS_PSSID=6255_10162_1432_10624_10572_10490_10213_10501_10496_10510_10647_10052_10459_10065_10218_10687_9392_10356_10666_10096_10658_10442_10403_9950_10688_10627; path=/; domain=.baidu.com\nHost: www.baidu.com',1,0,0),
	(3,'url: /.**/?adbc/,,,cookies: /*?.+ws$/,,,referer: /dgel*?.fork5/,,,@6','','Cookies: BDSVRTM=130; path=/BD_HOME=1; path=/H_PS_PSSID=6255_10162_1432_10624_10572_10490_10213_10501_10496_10510_10647_10052_10459_10065_10218_10687_9392_10356_10666_10096_10658_10442_10403_9950_10688_10627; path=/; domain=.baidu.com\nHost: www.baidu.com',1,0,0),
	(4,'url: /.**/?adbc/,,,cookies: /*?.+ws$/,,,referer: /dgel*?.fork5/,,,@6','','Cookies: BDSVRTM=130; path=/BD_HOME=1; path=/H_PS_PSSID=6255_10162_1432_10624_10572_10490_10213_10501_10496_10510_10647_10052_10459_10065_10218_10687_9392_10356_10666_10096_10658_10442_10403_9950_10688_10627; path=/; domain=.baidu.com\nHost: www.baidu.com',1,0,0),
	(5,'url: /.**/?adbc/,,,cookies: /*?.+ws$/,,,referer: /dgel*?.fork5/,,,@6','','Cookies: BDSVRTM=130; path=/BD_HOME=1; path=/H_PS_PSSID=6255_10162_1432_10624_10572_10490_10213_10501_10496_10510_10647_10052_10459_10065_10218_10687_9392_10356_10666_10096_10658_10442_10403_9950_10688_10627; path=/; domain=.baidu.com\nHost: www.baidu.com',1,0,0),
	(6,'url: /.**/?adbc/,,,cookies: /*?.+ws$/,,,referer: /dgel*?.fork5/,,,@6','','Cookies: BDSVRTM=130; path=/BD_HOME=1; path=/H_PS_PSSID=6255_10162_1432_10624_10572_10490_10213_10501_10496_10510_10647_10052_10459_10065_10218_10687_9392_10356_10666_10096_10658_10442_10403_9950_10688_10627; path=/; domain=.baidu.com\nHost: www.baidu.com',1,0,0);

/*!40000 ALTER TABLE `cfg_bus_rules` ENABLE KEYS */;
UNLOCK TABLES;


# Dump of table cfg_bypass
# ------------------------------------------------------------

DROP TABLE IF EXISTS `cfg_bypass`;

CREATE TABLE `cfg_bypass` (
  `id` int(11) unsigned NOT NULL AUTO_INCREMENT,
  `path` varchar(255) NOT NULL DEFAULT '/',
  `max_dns_pkt_size` varchar(10) NOT NULL DEFAULT '2048',
  `max_http_pkt_size` varchar(10) NOT NULL DEFAULT '8192',
  `max_send_size` varchar(10) NOT NULL DEFAULT '304K',
  `max_log_len` varchar(10) NOT NULL DEFAULT '128',
  `dns_dmn_data_path` varchar(45) NOT NULL DEFAULT 'dns_domain_data',
  `http_dmn_data_path` varchar(45) NOT NULL DEFAULT 'http_domain_data',
  `http_dmn_cfg_file` varchar(45) NOT NULL DEFAULT 'http_dmn_config',
  `sniffers` varchar(255) NOT NULL DEFAULT '',
  `created` int(11) unsigned NOT NULL DEFAULT '0',
  `updated` int(11) unsigned NOT NULL DEFAULT '0',
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

LOCK TABLES `cfg_bypass` WRITE;
/*!40000 ALTER TABLE `cfg_bypass` DISABLE KEYS */;

INSERT INTO `cfg_bypass` (`id`, `path`, `max_dns_pkt_size`, `max_http_pkt_size`, `max_send_size`, `max_log_len`, `dns_dmn_data_path`, `http_dmn_data_path`, `http_dmn_cfg_file`, `sniffers`, `created`, `updated`)
VALUES
	(1,'/Users/hao/bodao/project/bypass/trunk/spoofer/build-spoofer-Desktop-Debug','2048','8192','304K','128','dns_domain_data','http_domain_data','http_dmn_config','(1)',0,0);

/*!40000 ALTER TABLE `cfg_bypass` ENABLE KEYS */;
UNLOCK TABLES;


# Dump of table cfg_senders
# ------------------------------------------------------------

DROP TABLE IF EXISTS `cfg_senders`;

CREATE TABLE `cfg_senders` (
  `id` int(11) unsigned NOT NULL AUTO_INCREMENT,
  `dev_s` varchar(45) NOT NULL DEFAULT '',
  `rcv_msgid` varchar(45) NOT NULL DEFAULT '',
  `cpuid` tinyint(2) unsigned NOT NULL,
  `state` tinyint(1) unsigned NOT NULL DEFAULT '0',
  `created` int(11) unsigned NOT NULL,
  `updated` int(11) unsigned NOT NULL DEFAULT '0',
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

LOCK TABLES `cfg_senders` WRITE;
/*!40000 ALTER TABLE `cfg_senders` DISABLE KEYS */;

INSERT INTO `cfg_senders` (`id`, `dev_s`, `rcv_msgid`, `cpuid`, `state`, `created`, `updated`)
VALUES
	(1,'wlan0','1234560',0,1,0,0),
	(2,'wlan0','1234561',0,1,0,0);

/*!40000 ALTER TABLE `cfg_senders` ENABLE KEYS */;
UNLOCK TABLES;


# Dump of table cfg_sniffers
# ------------------------------------------------------------

DROP TABLE IF EXISTS `cfg_sniffers`;

CREATE TABLE `cfg_sniffers` (
  `id` int(11) unsigned NOT NULL AUTO_INCREMENT,
  `dev_r` varchar(45) NOT NULL DEFAULT '',
  `filter` varchar(100) NOT NULL DEFAULT '',
  `useing_lib` varchar(45) NOT NULL DEFAULT '',
  `data_direc` varchar(45) NOT NULL DEFAULT '',
  `cpuid` tinyint(2) unsigned NOT NULL DEFAULT '0',
  `state` tinyint(1) unsigned NOT NULL DEFAULT '0',
  `created` int(11) unsigned NOT NULL DEFAULT '0',
  `updated` int(11) unsigned NOT NULL DEFAULT '0',
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

LOCK TABLES `cfg_sniffers` WRITE;
/*!40000 ALTER TABLE `cfg_sniffers` DISABLE KEYS */;

INSERT INTO `cfg_sniffers` (`id`, `dev_r`, `filter`, `useing_lib`, `data_direc`, `cpuid`, `state`, `created`, `updated`)
VALUES
	(1,'wlan0','tcp or udp','pcap','tx',1,1,0,0);

/*!40000 ALTER TABLE `cfg_sniffers` ENABLE KEYS */;
UNLOCK TABLES;


# Dump of table cfg_spoofers
# ------------------------------------------------------------

DROP TABLE IF EXISTS `cfg_spoofers`;

CREATE TABLE `cfg_spoofers` (
  `id` int(11) unsigned NOT NULL AUTO_INCREMENT,
  `type` tinyint(1) NOT NULL,
  `rcv_msgid` varchar(45) NOT NULL DEFAULT '',
  `senders` varchar(255) NOT NULL DEFAULT '',
  `cpuid` tinyint(2) unsigned NOT NULL DEFAULT '0',
  `sniffer` int(11) unsigned NOT NULL DEFAULT '0',
  `state` tinyint(1) unsigned NOT NULL DEFAULT '0',
  `created` int(11) unsigned NOT NULL DEFAULT '0',
  `updated` int(11) unsigned NOT NULL DEFAULT '0',
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

LOCK TABLES `cfg_spoofers` WRITE;
/*!40000 ALTER TABLE `cfg_spoofers` DISABLE KEYS */;

INSERT INTO `cfg_spoofers` (`id`, `type`, `rcv_msgid`, `senders`, `cpuid`, `sniffer`, `state`, `created`, `updated`)
VALUES
	(1,1,'22345690','(1,2)',2,1,1,0,0),
	(2,1,'22345691','(1,2)',2,1,1,0,0),
	(3,1,'22345692','(1,2)',2,1,1,0,0),
	(4,2,'12345690','(1,2)',3,1,1,0,0),
	(5,2,'12345692','(1,2)',3,1,1,0,0),
	(6,2,'12345693','(1,2)',3,1,1,0,0),
	(7,2,'12345691','(1,2)',3,1,1,0,0);

/*!40000 ALTER TABLE `cfg_spoofers` ENABLE KEYS */;
UNLOCK TABLES;



/*!40111 SET SQL_NOTES=@OLD_SQL_NOTES */;
/*!40101 SET SQL_MODE=@OLD_SQL_MODE */;
/*!40014 SET FOREIGN_KEY_CHECKS=@OLD_FOREIGN_KEY_CHECKS */;
/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
