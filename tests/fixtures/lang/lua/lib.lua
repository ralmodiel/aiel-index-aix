local M = {}
function M.add(a, b) return a + b end
function M:run(x) return self:helper(x) end
function M:helper(x) return M.add(x, 1) end
return M
