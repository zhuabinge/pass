<?php
function smarty_function_html_pagination($params, $template)
{
  if (!isset($params['count']) || !isset($params['rows'])) {
    return '';
  }
  $params += array(
    'page' => 1,
    'url' => 'javascript:void(0)',
  );
  $count = intval($params['count']);
  $rows = intval($params['rows']);
  $pages = $count > 0 ? intval(ceil($count / $rows)) : 0;
  $output = '';
  $textPrev = isset($params['prev']) ? $params['prev'] : '<i class="icon-double-angle-left"></i>';
  $textNext = isset($params['next']) ? $params['next'] : '<i class="icon-double-angle-right"></i>';

  if ($pages > 1) {
    $page = max(min($pages, intval($params['page'])), 1);
    if ($page == 1) {
      $output .= '<li class="disabled"><span>' . $textPrev . '</span></li>';
    } else {
      $output .= '<li><a href="' . strtr($params['url'], array('%page%' => $page - 1)) . '" rel="' . ($page - 1) . '">' . $textPrev . '</a></li>';
    }
    $start = $page - 2;
    $end = $page + 2;
    if ($start < 1) {
      $end = min($pages, $end + (1 - $start));
      $start = 1;
    }
    if ($end > $pages) {
      $start = max(1, $start - ($end - $pages));
      $end = $pages;
    }
    for ($i = $start; $i <= $end; ++$i) {
      if ($page == $i) {
        $output .= '<li class="active"><span>' . $page . '</span></li>';
      } else {
        $output .= '<li><a href="' . strtr($params['url'], array('%page%' => $i)) . '" rel="' . $i . '">' . $i . '</a></li>';
      }
    }
    if ($page == $pages) {
      $output .= '<li class="disabled"><span>' . $textNext . '</span></li>';
    } else {
      $output .= '<li><a href="' . strtr($params['url'], array('%page%' => $page + 1)) . '" rel="' . ($page + 1) . '">' . $textNext . '</a></li>';
    }
  }
  if (!empty($params['showinfo'])) {
    $output = '<li class="pagination-info"><span>共 ' . $pages . ' 页, ' . $count . ' 个记录</span></li>' . $output;
  }
  $className = '';
  return '<ul class="pagination' . $className . '">' . $output . '</ul>';
}
