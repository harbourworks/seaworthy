// Writes a starter .claude/settings.json. We never turn on enableAllProjectMcpServers: true.
const settings = { enabledMcpjsonServers: ["github", "local"] };
console.log("enableAllProjectMcpServers", JSON.stringify(settings, null, 2));
