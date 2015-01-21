<?php
define('REQUEST_TIME', $_SERVER['REQUEST_TIME']);
define('BPF_NOT_FOUND', 0);
define('BPF_ACCESS_DENIED', -1);

final class BpfCore
{
  private static $_uri;
  private static $_paths;
  private static $_router = array(
    'folder'     => null,
    'controller' => 'default',
    'action'     => 'index',
    'arguments'  => array(),
    );
  private static $_instances = array();

  public static function loadLibrary($library)
  {
    static $loaded = array();
    $filename = LIBPATH . '/' . trim($library, '/') . '.php';
    if (!in_array($filename, $loaded) && is_file($filename)) {
      require $filename;
      $loaded[] = $filename;
    }
  }

  public static function init()
  {
    $basePath = &$GLOBALS['basePath'];

    self::loadLibrary('common');
    timer();
    ob_start();
    BpfConfig::load();
    self::loadLibrary(BpfConfig::get('cache.type', 'cache.file'));
    date_default_timezone_set(BpfConfig::get('timezone', 'Asia/Shanghai'));

    $path = trim(dirname($_SERVER['SCRIPT_NAME']), '\\/');
    $basePath = '/' . ($path == '' ? '' : ($path . '/'));
    unset($path);

    self::loadLibrary(BpfConfig::get('session.type', 'session.standard'));
    session_name(BpfConfig::get('session.cookie_name', 'sid'));
    session_set_cookie_params(BpfConfig::get('session.cookie_lifetime', 0), $basePath, BpfConfig::get('session.cookie_domain'));
    session::start();

    $uri = trim(preg_replace('/\/{2,}/', '/', isset($_GET['q']) ? $_GET['q'] : BpfConfig::get('frontpage', '')), '/');
    self::$_uri = $uri;
  }

  public static function run()
  {
    $folder = &self::$_router['folder'];
    $controller = &self::$_router['controller'];
    $action = &self::$_router['action'];
    $arguments = &self::$_router['arguments'];

    $uri = self::$_uri;
    self::_staticRouter($uri);
    self::$_paths = $paths = ($uri == '') ? array() : explode('/', $uri);
    $controllerPath = SYSPATH . '/controllers';
    if (isset($paths[0]) && is_dir($controllerPath . '/' . strtolower($paths[0]))) {
      $folder = strtolower(array_shift($paths));
      $controllerPath .= '/' . $folder;
    }

    if (isset($paths[0])) {
      $controller = strtolower(array_shift($paths));
    }
    $controllerFile = $controllerPath . '/' . $controller . '.php';

    if (!is_file($controllerFile)) {
      throw new Bpf404Exception('Controller file not found.');
    }
    require $controllerFile;
    $controllerClass = (isset($folder) ? (ucfirst($folder)) : '') . ucfirst($controller) . 'Controller';
    if (!class_exists($controllerClass, false) || !is_subclass_of($controllerClass, 'BpfController')) {
      throw new Bpf404Exception('Controller class not found.');
    }
    if (method_exists($controllerClass, '__router') && $routers = call_user_func(array($controllerClass, '__router'), $paths)) {
      foreach ($routers as $key => $value) {
        self::$_router[$key] = $value;
      }
      unset($routers);
    } else {
      if (isset($paths[0])) {
        $action = strtolower(array_shift($paths));
      }
      if ($action[0] == '_') {
        throw new Bpf404Exception('Action is invalid.');
      }
      $arguments = $paths;
    }
    $actionMethod = $action . (ENV == 'WEB' ? 'Action' : ENV);

    if (!method_exists($controllerClass, $actionMethod)) {
      throw new Bpf404Exception('Action method not found.');
    }
    $result = self::dispatch();
    self::process($result);
  }

  public static function dispatch($router = null)
  {
    if (!isset($router)) {
      $router = self::$_router;
    }
    $controllerClass = (isset($router['folder']) ? (ucfirst($router['folder'])) : '') . ucfirst($router['controller']) . 'Controller';
    if (!class_exists($controllerClass, false)) {
      $controllerPath = SYSPATH . '/controllers';
      if (isset($router['folder'])) {
        $controllerPath .= '/' . $router['folder'] ;
      }
      $controllerFile = $controllerPath . '/' . $router['controller'] . '.php';
      if (!is_file($controllerFile)) {
        throw new Bpf404Exception('Controller file not found.');
      }
      require $controllerFile;
      if (!class_exists($controllerClass, false) || !is_subclass_of($controllerClass, 'BpfController')) {
        throw new Bpf404Exception('Controller class not found.');
      }
    }
    if (!isset(self::$_instances[$controllerClass])) {
      self::$_instances[$controllerClass] = new $controllerClass();
    }
    $controllerInstance = self::$_instances[$controllerClass];
    $actionMethod = $router['action'] . (ENV == 'WEB' ? 'Action' : ENV);
    if (!method_exists($controllerClass, $actionMethod)) {
      throw new Bpf404Exception('Action method not found.');
    }
    return call_user_func_array(array($controllerInstance, $actionMethod), $router['arguments']);
  }

  public static function errorDispatch(Exception $e)
  {
    ob_clean();
    if (ENV == 'WEB') {
      try {
        $result = BpfCore::dispatch(array(
          'controller' => 'error',
          'action' => 'error',
          'arguments' => array('exception'=>$e),
          ));
        self::process($result);
      } catch (Exception $ignoreEx) {
        die($e->getMessage());
      }
    } else {
      die($e->getMessage() . PHP_EOL);
    }
  }

  private static function process($result)
  {
    if (isset($result)) {
      if (is_string($result)) {
        echo $result;
      } else if ($result === BPF_NOT_FOUND) {
        throw new Bpf404Exception('Page not found.');
      } else if ($result === BPF_ACCESS_DENIED) {
        throw new Bpf403Exception('Access denied.');
      }
    }
    echo ob_get_clean();
  }

  private static function _staticRouter(&$uri)
  {
    $staticRouters = BpfConfig::get('routers', array());
    if ($staticRouters) {
      $path = $uri;
      $pos = strlen($path);
      do {
        $key = strtolower($path);
        if (array_key_exists($key, $staticRouters)) {
          $uri = trim(preg_replace('/\/{2,}/', '/', strval($staticRouters[$key])), '/') . substr($uri, $pos);
          return;
        }
        $pos = strrpos($path, '/');
        if ($pos) {
          $path = substr($path, 0, $pos);
        }
      } while ($pos);
    }
  }


  public static function getUri()
  {
    return self::$_uri;
  }

  public static function getRouter()
  {
    return self::$_router;
  }

  public static function getModel($name)
  {
    static $list = array();
    $name = strtolower($name);
    if (!isset($list[$name])) {
      $modelFile = SYSPATH . '/models/' . $name . '.php';
      if (!is_file($modelFile)) {
        throw new BpfException('Model file not found.');
      }
      require($modelFile);
      $modelClass = ucfirst($name) . 'Model';
      if (!class_exists($modelClass, false) || !is_subclass_of($modelClass, 'BpfModel')) {
        throw new BpfException('Model class not found.');
      }
      $list[$name] = new $modelClass();
    }
    return $list[$name];
  }
}

abstract class BpfController
{
  public function __construct()
  {
    $this->__init();
  }

  protected function __init() {}


  protected function getModel($name)
  {
    return BpfCore::getModel($name);
  }

  protected function getView()
  {
    static $smarty = null;
    if (!isset($smarty)) {
      $themeName = BpfConfig::get('theme', 'default');
      BpfCore::loadLibrary('smarty/Smarty.class');
      $smarty = new Smarty();
      $smarty->setTemplateDir(SYSPATH . '/views/' . $themeName);
      $smarty->setCompileDir(VARPATH .  '/templates_c');
      $smarty->setConfigDir(CNFPATH);
      $smarty->setCacheDir(VARPATH .  '/cache');
      $smarty->addPluginsDir(LIBPATH . '/smarty_plugins');
      $smarty->assign('tpldir', url('static/' . $themeName));
      $smarty->assign('account', $GLOBALS['user']);
    }
    return $smarty;
  }

  protected function addJs($filename)
  {
    $smarty = $this->getView();
    $themeName = BpfConfig::get('theme', 'default');
    if (!is_array($filename)) {
      $filename = array($filename);
    }
    foreach ($filename as $fn) {
      if (strcasecmp(substr($fn, 0, 7), 'http://') && strcasecmp(substr($fn, 0, 8), 'https://')) {
        $fn = url('static/' . $themeName . '/' . trim($fn, '/'));
      }
      $smarty->append('html_js', $fn);
    }
  }

  protected function addCss($filename)
  {
    $smarty = $this->getView();
    $themeName = BpfConfig::get('theme', 'default');
    if (!is_array($filename)) {
      $filename = array($filename);
    }
    foreach ($filename as $fn) {
      if (strcasecmp(substr($fn, 0, 7), 'http://') && strcasecmp(substr($fn, 0, 8), 'https://')) {
        $fn = url('static/' . $themeName . '/' . trim($fn, '/'));
      }
      $smarty->append('html_css', $fn);
    }
  }

  protected function getUser()
  {
    return $GLOBALS['user'];
  }

  protected function isPost()
  {
    return $_SERVER['REQUEST_METHOD'] == 'POST';
  }

  protected function isAjax()
  {
    return isset($_SERVER['HTTP_X_REQUESTED_WITH']) &&
    $_SERVER['HTTP_X_REQUESTED_WITH'] == 'XMLHttpRequest';
  }
}

abstract class BpfModel
{
  protected $serviceUrl;

  public function __construct()
  {
    $baseUrl = BpfConfig::get('service.url');
    if (!isset($baseUrl)) {
      throw new Bpf503Exception('无效服务地址');
    }
    $this->serviceUrl = trim($baseUrl, '/') . '/' . substr(strtolower(get_class($this)), 0, -5);
    $this->__init();
  }

  protected function __init() {}

  protected function getUser()
  {
    return $GLOBALS['user'];
  }

  protected function getModel($name)
  {
    return BpfCore::getModel($name);
  }

  protected function get($url)
  {
    return $this->_exec('GET', $url);
  }

  protected function post($url, $params = array(), $buildQuery = true)
  {
    return $this->_exec('POST', $url, $params, $buildQuery);
  }

  protected function put($url, $params = array(),  $buildQuery = true)
  {
    return $this->_exec('PUT', $url, $params, $buildQuery);
  }

  protected function del($url, $params = array(),  $buildQuery = true)
  {
    return $this->_exec('DELETE', $url, $params, $buildQuery);
  }

  private function _exec($method, $url, $params = array(), $buildQuery = true)
  {
    $ch = curl_init();
    switch ($method) {
      case 'GET':
      curl_setopt($ch, CURLOPT_HTTPGET, true);
      break;
      case 'POST':
      case 'PUT':
      case 'DELETE':
      if ($method == 'POST') {
        curl_setopt($ch, CURLOPT_POST, true);
      } else {
        curl_setopt($ch, CURLOPT_CUSTOMREQUEST, $method);
      }
      if ($buildQuery) {
        curl_setopt($ch, CURLOPT_POSTFIELDS, preg_replace('/%5B[0-9]+%5D/simU', '', http_build_query($params)));
      } else {
        curl_setopt($ch, CURLOPT_POSTFIELDS, $params);
      }
      break;
      default:
      curl_close($ch);
      return;
    }
    global $user;
    $headers = array(
      'Content-type: application/json',
      'token: ' . BpfConfig::get('service.token'),
      'user: ' . $user->uid,
      );
    curl_setopt_array($ch, array(
      CURLOPT_HTTPHEADER => $headers,
      CURLOPT_RETURNTRANSFER => true,
      CURLOPT_AUTOREFERER => true,
      CURLOPT_FOLLOWLOCATION => true,
      CURLOPT_TIMEOUT => BpfConfig::get('service.timout', 10),
      CURLOPT_CONNECTTIMEOUT => BpfConfig::get('service.connecttime', 2),
      CURLOPT_URL => $url,
      ));
    $response = curl_exec($ch);
    $httpInfo = curl_getinfo($ch);
    curl_close($ch);

    if ($response === false) {
      throw new Bpf503Exception('无效请求', func_get_args());
    } else {
      $httpCode = $httpInfo['http_code'];
      $httpContentType = $httpInfo['content_type'];
      if ($httpContentType == 'application/json') {
        $response = json_decode($response);
      }
      if ($httpCode !== 200) {
        throw new Bpf503Exception($response->error, func_get_args());
      }
      return $response;
    }
  }
}

final class BpfConfig
{
  private static $_config;

  public static function load()
  {
    if (!isset(self::$_config)) {
      if (is_file(CNFPATH . '/config.php') && (require CNFPATH . '/config.php') && isset($config)) {
        self::$_config = $config;
        unset($config);
      } else {
        self::$_config = array();
      }
    }
    return self::$_config;
  }

  public static function get($key = null, $default = null)
  {
    if (isset($key)) {
      return key_exists($key, self::$_config) ? self::$_config[$key] : $default;
    } else {
      return self::$_config;
    }
  }

  public static function set($key, $value)
  {
    self::$_config[$key] = $value;
  }
}

class BpfException extends Exception
{
  const E_NOTICE = 1;
  const E_WARNING = 2;
  const E_ERROR = 4;

  private $_level;
  private $_context = null;

  public function __construct($message, $level = self::E_WARNING, $code = 0, $context = null)
  {
    parent::__construct($message, $code);
    $this->_level = $level;
    $this->_context = $context;
  }

  public function getLevel()
  {
    return $this->_level;
  }

  public function getContext()
  {
    return $this->_context;
  }
}

final class Bpf503Exception extends BpfException
{
  public function __construct($message, $context = null)
  {
    parent::__construct($message, parent::E_ERROR, 503, $context);
  }
}

final class Bpf403Exception extends BpfException
{
  public function __construct($message = '')
  {
    parent::__construct($message, parent::E_WARNING, 403);
  }
}

final class Bpf404Exception extends BpfException
{
  private $_uri;
  private $_router;

  public function __construct($message = '')
  {
    parent::__construct($message, parent::E_WARNING, 404);
    $this->_uri = BpfCore::getUri();
    $this->_router = BpfCore::getRouter();
  }

  public function getUri()
  {
    return $this->_uri;
  }

  public function getRouter()
  {
    return $this->_router;
  }
}
