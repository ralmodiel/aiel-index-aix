---
description: What the current diff touches and which tests or UI strings it could break (aix impact)
argument-hint: [rev, default HEAD]
---
Run `aix impact $ARGUMENTS`. Report the affected routes, the e2e scenarios to run (with their roles), the
scripts that hit touched endpoints, and every removed UI string that a test still quotes.
