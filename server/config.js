module.exports = {
  server: {
    // hostname: '127.0.0.1',
    port: 8080,
    worker_processes: 1,
//    daemonize: true,
    token: '12345678'
  },
  service: [
    'mysql',
    'cache',
    'config',
//    'queue',
  ],
  mysql: {
    host: '127.0.0.1',
    port: 3306,
    user: 'root',
    password: '',
    name: 'bypass',
    log_query: 1
  },
  cache: {
    host: '127.0.0.1',
    port: 6379,
    lifetime: 1800,
  },
  queue: [
    'sysinfoUpdate',
  ],
};
