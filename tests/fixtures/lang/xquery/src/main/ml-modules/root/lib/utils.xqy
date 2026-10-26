xquery version "1.0-ml";

(:~
 : Utility module. (: a nested comment: declare function u:fake($x) { u:greet("no") }; :)
 :)
module namespace u = "http://example.com/utils";

import module namespace other = "http://example.com/other" at "other.xqy";

declare namespace html = "http://www.w3.org/1999/xhtml";
declare option xdmp:mapping "false";

declare variable $u:LIMIT as xs:integer := 10;
declare variable $u:CONFIG external;

(: u:greet( in a comment is not a call :)
declare function u:greet($name as xs:string) as xs:string
{
  fn:concat("Hello, foo:bar(", $name, "'s u:greet(""quoted"")")
};

declare function u:greet($name as xs:string, $title as xs:string?) as xs:string
{
  u:greet(fn:string-join(($title, $name), " "))
};

declare %private function u:helper($x) as element(div)
{
  <div class="{u:greet($x)}" title="u:greet(attr text)">
    text with u:greet( inside xml and {{literal braces}}
    { other:shout($x, $u:LIMIT) }
    <!-- u:greet( in an xml comment -->
    <![CDATA[ u:greet( in cdata ]]>
  </div>
};

declare %rest:path("/apply") function u:apply() {
  let $f := u:greet#1
  return ($f("x"), u:helper("y"), other:greet("z"))
};
