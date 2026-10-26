xquery version "1.0-ml";
let $url := xdmp:get-request-url()
return
  if (fn:matches($url, "^/report/")) then "/app/report.xqy"
  else fn:replace($url, "^/legacy/(.*)$", "/app/main.xqy?page=$1")
