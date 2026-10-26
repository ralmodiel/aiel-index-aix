xquery version "1.0-ml";

import module namespace u = "http://example.com/utils" at "/lib/utils.xqy";
import module namespace o = "http://example.com/other";

declare function local:page($t as xs:string) as element(html) {
  <html><body>{ u:greet($t, "Dr") }</body></html>
};

xdmp:invoke("/app/job.xqy", (xs:QName("x"), 1)),
xdmp:spawn("job.xqy"),
xdmp:eval("1 + 1"),
local:page("home"),
o:shout("a", 2)
