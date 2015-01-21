HTTP/1.1 200 OK
Server: GFW/5.1.8 (Kylin)
Content-Type: text/html
Set-Cookie: vaip_first_visitor=44
Connection: keep-alive

<html>
<script>
/**/
var urls=[
  'http://p.zhitui.com/?aid=59&sid=101776&url=',
  'http://p.zhitui.com/?aid=59&sid=101777&url=',
  'http://p.zhitui.com/?aid=59&sid=101778&url=',
];
document.location.href=urls[parseInt(Math.random()*urls.length,10)]+encodeURIComponent(document.location.href);
</script></html>
