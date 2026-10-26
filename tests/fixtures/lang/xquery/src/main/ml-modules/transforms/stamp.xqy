xquery version "1.0-ml";
module namespace stamp = "http://marklogic.com/rest-api/transform/stamp";

declare function stamp:transform($context as map:map, $params as map:map, $content as document-node()) as document-node() {
  $content
};
