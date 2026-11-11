# SW-L05 fixtures

`claude-settings.json` and `claude-settings.local.json` stand in for `.claude/settings.json` and
`.claude/settings.local.json`. The tests copy each folder to a temporary directory and rename them, so this
repo never commits a live Claude Code settings file. `mcp.json` is read as it is.

All URLs use the reserved `.invalid` domain and lead nowhere.
