<?php
function smarty_function_html_css($params, $template)
{
  $vars = $template->getTemplateVars();
  if (isset($vars['html_css'])) {
    $output = array();
    foreach ($vars['html_css'] as $css) {
      $output[] = '<link rel="stylesheet" type="text/css" media="screen" href="' . htmlspecialchars($css) . '">';
    }
    return implode(PHP_EOL, $output);
  }
}
