<?php
function smarty_function_html_messages($params, $template)
{
  $messages = getMessages();
  $output = array();
  foreach ($messages as $message) {
    if ($message['type'] == 'error') {
      $class = 'alert-danger';
    } else if ($message['type'] == 'success') {
      $class = 'alert-success';
    } else if ($message['type'] == 'warning') {
      $class = 'alert-warning';
    } else {
      $class = 'alert-info';
    }
    $output[] = <<<HTML
<div class="alert {$class} fade in">
  <i class="icon-remove close" data-dismiss="alert"></i>
  {$message['value']}
</div>
HTML;
  }
  return implode(PHP_EOL, $output);
}
