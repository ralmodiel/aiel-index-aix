xquery version "1.0-ml";
(: an older copy of the same module elsewhere in the repo :)
module namespace u = "http://example.com/utils";

declare function u:greet($name as xs:string) as xs:string { "hi " || $name };
