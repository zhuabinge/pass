<?php
function smarty_function_html_js($params, $template)
{
  $vars = $template->getTemplateVars();
  if (isset($vars['html_js'])) {
    $output = array();
    foreach ($vars['html_js'] as $js) {
      $output[] = '<script type="text/javascript" src="' . htmlspecialchars($js) . '"></script>';
    }
    return implode(PHP_EOL, $output);
  }
}
