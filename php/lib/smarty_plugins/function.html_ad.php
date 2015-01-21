<?php
function smarty_function_html_ad($params, $template)
{
  if (!isset($params['id']) || !isset($params['width']) || !isset($params['height']) ||
      !is_numeric($params['width']) || !is_numeric($params['height'])) {
    return '';
  }
  $id = trim($params['id']);
  $adModel = BpfCore::getModel('ad');
  $ad = $adModel->getAdBySocketId($id);
  if (!$ad) {
    return '';
  }
  if ($ad->type == 1) {
    // 普通广告
    $className = array(
      'banner-socket',
      'banner-' . $id,
    );
    if (isset($params['class'])) {
      $className = array_merge($className, explode(' ', $params['class']));
    }
    $className = array_unique($className);
    $target = '';
    if (isset($params['target'])) {
      $target = 'target="_blank"';
    }
    return '<a ' . $target . ' href="' . $ad->link . '" class="' . implode(' ', $className) . '"><img src="' .
        urlStatic($ad->image_path) . '" width="' . intval($params['width']) . '" height="' .
        intval($params['height']) . '"></a>';
  } else {
    // 联盟广告
    return $ad->code;
  }
}
