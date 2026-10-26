---
description: Everything to know before editing a route, menu page or file (aix brief)
argument-hint: <route | menu label | file>
---
Run `aix brief $ARGUMENTS` (or the `aix` MCP tool with command "brief") and use its answer as the
starting point: who can see the page, which endpoints it calls with what roles, which e2e scenarios and
scripts cover it, past findings, recent fix commits and open decisions. Read only the file ranges it points to.
