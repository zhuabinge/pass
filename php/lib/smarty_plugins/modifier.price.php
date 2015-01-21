<?php
function smarty_modifier_price($params)
{
  list($yuan, $fen) = explode('.', $params);
  $output = '<em><b>¥</b>' . $yuan;
  if (isset($fen) && intval($fen)) {
    $output .= '<i>.' . substr(preg_replace('/0$/', '', $fen),0,1) . '</i>';
  }
  $output .= '</em>';
  return $output;
}
