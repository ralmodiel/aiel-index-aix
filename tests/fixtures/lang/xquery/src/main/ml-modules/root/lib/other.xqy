xquery version "1.0-ml";
module namespace other = "http://example.com/other";

declare function other:shout($s as xs:string, $n as xs:integer) as xs:string {
  fn:upper-case($s) || xs:string($n)
};

declare function other:greet($x) { "other " || $x };
