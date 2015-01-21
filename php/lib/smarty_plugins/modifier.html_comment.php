<?php
function smarty_modifier_html_comment($comment)
{
  if(empty($comment)) {
   return '';
  }
  $badword = array(
    '傻叉',
    'sb',
    'tm',
    'fuck',
    'gan',
    '阿阿',
    '喔噢',
  );
  $badword1 = array_combine($badword,array_fill(0,count($badword),'***'));
  return strtr($comment, $badword1);
}
