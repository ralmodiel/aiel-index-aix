xquery version "1.0-ml";
module namespace hello = "http://marklogic.com/rest-api/resource/hello";

import module namespace u = "http://example.com/utils" at "/lib/utils.xqy";

declare function hello:get($context as map:map, $params as map:map) as document-node()* {
  document { <greeting>{ u:greet(map:get($params, "name")) }</greeting> }
};

declare function hello:post($context as map:map, $params as map:map, $input as document-node()*) as document-node()? {
  ()
};
