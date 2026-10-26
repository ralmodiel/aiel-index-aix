'use strict';
const tools = require("/lib/tools.sjs");
const { twice } = require("/lib/tools.sjs");

function get(context, params) {
  return tools.twice(params.n) + twice(1);
}

exports.GET = get;
