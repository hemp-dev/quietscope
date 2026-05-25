package checks

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/hemp-dev/quietscope/internal/audit"
	"github.com/hemp-dev/quietscope/internal/platform"
	"github.com/hemp-dev/quietscope/internal/safety"
	toml "github.com/pelletier/go-toml/v2"
	"gopkg.in/yaml.v3"
)

type AIToolDefinition struct {
	ID             string
	DisplayName    string
	Vendor         string
	Categories     []string
	AppPaths       []string
	BinaryNames    []string
	ConfigPaths    []string
	CachePaths     []string
	LogPaths       []string
	ProjectMarkers []string
	Ports          []int
	ProcessNames   []string
	RiskNotes      []string
}

type AIModelProviderDefinition struct {
	ID              string
	DisplayName     string
	CountryOrRegion string
	Vendor          string
	Families        []string
	APIEnvKeys      []string
	ConfigPaths     []string
	CachePaths      []string
	ModelCacheHints []string
	CLINames        []string
	RiskNotes       []string
}

type parsedMCPServer struct {
	ServerName string
	Command    string
	Args       []string
	Transport  string
	URL        string
	EnvKeys    []string
	ConfigPath string
	Scope      string
}

func RunAIToolsCatalog(ctx context.Context, cfg audit.RuntimeConfig, runner *platform.Runner) (audit.CheckResult, error) {
	tools := detectAIToolCatalog(cfg)
	clients := detectMCPClients(cfg)
	servers := detectMCPServers(cfg)
	hermes := detectHermesAgent(cfg)
	opencode := detectOpenCode(cfg)
	providers := detectChineseAIProviders(cfg)
	models := detectLocalModelInventory(cfg, providers)
	securityTools := detectAISecurityTools(cfg)
	findings := aiToolCatalogFindings(tools, clients, servers, hermes, opencode, providers, models, securityTools)
	summary := calculateAIProviderSummary(ctx, runner, tools, clients, servers, hermes, opencode, providers, models)
	manageable := manageableForMCPServers(servers, cfg)
	manageable = append(manageable, manageableForLocalModels(models, cfg)...)
	return audit.CheckResult{
		Findings:            findings,
		ManageableArtifacts: manageable,
		AIToolCatalog:       tools,
		MCPClients:          clients,
		MCPServers:          servers,
		HermesAgent:         hermes,
		OpenCode:            opencode,
		ChineseAIProviders:  providers,
		LocalModelInventory: models,
		AISecurityTools:     securityTools,
		AIProviderSummary:   summary,
	}, nil
}

func AIToolDefinitions(home string) []AIToolDefinition {
	app := func(name string) string { return filepath.Join("/Applications", name) }
	userApp := func(name string) string { return filepath.Join(home, "Applications", name) }
	return []AIToolDefinition{
		{ID: "claude-code", DisplayName: "Claude Code", Vendor: "Anthropic", Categories: []string{"ai_cli_agent", "ai_coding_agent", "mcp_client"}, AppPaths: []string{app("Claude.app"), app("Claude Desktop.app"), userApp("Claude.app")}, BinaryNames: []string{"claude"}, ConfigPaths: []string{filepath.Join(home, ".claude"), filepath.Join(home, "Library", "Application Support", "Claude"), filepath.Join(home, "Library", "Application Support", "Claude Code")}, CachePaths: []string{filepath.Join(home, "Library", "Caches", "Claude")}, LogPaths: []string{filepath.Join(home, "Library", "Logs", "Claude")}, ProjectMarkers: []string{"CLAUDE.md", ".claude"}, ProcessNames: []string{"Claude"}, RiskNotes: []string{"May load user/project instructions, commands, skills, memory, and MCP configs."}},
		{ID: "openai-codex", DisplayName: "OpenAI Codex CLI", Vendor: "OpenAI", Categories: []string{"ai_cli_agent", "ai_coding_agent", "cloud_agent_cli"}, BinaryNames: []string{"codex", "chatgpt"}, ConfigPaths: []string{filepath.Join(home, ".codex")}, ProjectMarkers: []string{"AGENTS.md", ".codex"}, RiskNotes: []string{"Project instructions and local session artifacts can influence agent behavior."}},
		{ID: "github-copilot", DisplayName: "GitHub Copilot", Vendor: "GitHub", Categories: []string{"ai_extension", "ai_coding_agent", "cloud_agent_cli"}, BinaryNames: []string{"gh", "copilot"}, ConfigPaths: []string{filepath.Join(home, ".config", "gh"), filepath.Join(home, "Library", "Application Support", "Code")}, ProjectMarkers: []string{filepath.Join(".github", "copilot-instructions.md")}, RiskNotes: []string{"Copilot instructions can affect coding-agent behavior."}},
		{ID: "cursor", DisplayName: "Cursor", Vendor: "Anysphere", Categories: []string{"ai_ide", "ai_coding_agent", "mcp_client", "ai_skill_host"}, AppPaths: []string{app("Cursor.app"), userApp("Cursor.app")}, BinaryNames: []string{"cursor"}, ConfigPaths: []string{filepath.Join(home, ".cursor"), filepath.Join(home, "Library", "Application Support", "Cursor")}, CachePaths: []string{filepath.Join(home, "Library", "Caches", "Cursor"), filepath.Join(home, "Library", "Caches", "com.todesktop.230313mzl4w4u92")}, LogPaths: []string{filepath.Join(home, "Library", "Logs", "Cursor")}, ProjectMarkers: []string{".cursor", ".cursorrules"}, Ports: []int{3000, 5000, 8000, 8080}, ProcessNames: []string{"Cursor"}, RiskNotes: []string{"Project rules and MCP configs can be auto-loaded depending on trust settings."}},
		{ID: "windsurf", DisplayName: "Windsurf", Vendor: "Codeium", Categories: []string{"ai_ide", "ai_coding_agent", "mcp_client"}, AppPaths: []string{app("Windsurf.app"), userApp("Windsurf.app")}, BinaryNames: []string{"windsurf"}, ConfigPaths: []string{filepath.Join(home, ".windsurf"), filepath.Join(home, "Library", "Application Support", "Windsurf")}, CachePaths: []string{filepath.Join(home, "Library", "Caches", "Windsurf")}, LogPaths: []string{filepath.Join(home, "Library", "Logs", "Windsurf")}, ProjectMarkers: []string{".windsurf", ".windsurfrules"}, RiskNotes: []string{"Rules and cloud/local coding-agent state may influence context."}},
		{ID: "google-antigravity", DisplayName: "Google Antigravity / Antigravity CLI", Vendor: "Google", Categories: []string{"ai_ide", "ai_coding_agent", "mcp_client", "cloud_agent_cli"}, AppPaths: []string{app("Google Antigravity.app"), userApp("Google Antigravity.app")}, BinaryNames: []string{"agy"}, ConfigPaths: []string{filepath.Join(home, ".antigravity"), filepath.Join(home, ".gemini", "antigravity"), filepath.Join(home, ".gemini", "antigravity", "mcp_config.json"), filepath.Join(home, ".gemini", "antigravity-cli"), filepath.Join(home, ".gemini", "antigravity-cli", "settings.json"), filepath.Join(home, ".gemini", "antigravity-cli", "mcp_config.json")}, ProjectMarkers: []string{".antigravity", filepath.Join(".agents", "mcp_config.json"), filepath.Join(".agents", "skills")}, RiskNotes: []string{"May connect remote model providers to local project/tool context."}},
		{ID: "cline", DisplayName: "Cline", Vendor: "Cline", Categories: []string{"ai_extension", "ai_coding_agent", "mcp_client"}, BinaryNames: []string{"cline"}, ConfigPaths: []string{filepath.Join(home, ".cline")}, ProjectMarkers: []string{".cline"}, RiskNotes: []string{"Can pair remote models with local file/shell/browser tools."}},
		{ID: "roo-code", DisplayName: "Roo Code / Roo Coder", Vendor: "Roo", Categories: []string{"ai_extension", "ai_coding_agent", "mcp_client"}, BinaryNames: []string{"roo"}, ConfigPaths: []string{filepath.Join(home, ".roo")}, ProjectMarkers: []string{".roo"}, RiskNotes: []string{"Can run with broad tool permissions if configured."}},
		{ID: "continue", DisplayName: "Continue.dev", Vendor: "Continue", Categories: []string{"ai_extension", "ai_coding_agent", "mcp_client"}, BinaryNames: []string{"continue"}, ConfigPaths: []string{filepath.Join(home, ".continue"), filepath.Join(home, ".config", "continue"), filepath.Join(home, "Library", "Application Support", "Continue")}, ProjectMarkers: []string{".continue"}, RiskNotes: []string{"Model/provider configs can include local and remote models."}},
		{ID: "aider", DisplayName: "Aider", Vendor: "Aider", Categories: []string{"ai_cli_agent", "ai_coding_agent"}, BinaryNames: []string{"aider"}, ConfigPaths: []string{filepath.Join(home, ".aider.conf.yml"), filepath.Join(home, ".aiderignore")}, ProjectMarkers: []string{".aider.conf.yml", ".aiderignore"}, RiskNotes: []string{"CLI coding agent can edit files and use remote providers."}},
		{ID: "open-interpreter", DisplayName: "Open Interpreter", Vendor: "Open Interpreter", Categories: []string{"ai_cli_agent", "ai_workflow_agent"}, BinaryNames: []string{"interpreter", "open-interpreter"}, ConfigPaths: []string{filepath.Join(home, ".open-interpreter")}, ProjectMarkers: []string{".open-interpreter"}, RiskNotes: []string{"Can execute local code when explicitly allowed by user configuration."}},
		{ID: "goose", DisplayName: "Goose", Vendor: "Block", Categories: []string{"ai_cli_agent", "ai_coding_agent", "mcp_client", "agent_orchestrator"}, AppPaths: []string{app("Goose.app")}, BinaryNames: []string{"goose"}, ConfigPaths: []string{filepath.Join(home, ".goose"), filepath.Join(home, ".config", "goose")}, ProjectMarkers: []string{".goose"}, RiskNotes: []string{"Agent orchestrator may connect MCP tools to model providers."}},
		{ID: "openclaw", DisplayName: "OpenClaw", Vendor: "OpenClaw", Categories: []string{"ai_cli_agent", "ai_coding_agent"}, BinaryNames: []string{"openclaw"}, ConfigPaths: []string{filepath.Join(home, ".openclaw")}, ProjectMarkers: []string{".openclaw"}, RiskNotes: []string{"Local agent artifacts can influence tool use."}},
		{ID: "devin-local-artifacts", DisplayName: "Devin local artifacts", Vendor: "Cognition", Categories: []string{"cloud_agent_cli", "ai_coding_agent"}, ConfigPaths: []string{filepath.Join(home, ".devin"), filepath.Join(home, ".config", "devin")}, ProjectMarkers: []string{".devin", "devin.json", ".github", filepath.Join(".github", "workflows")}, RiskNotes: []string{"Hosted agent local/session artifacts are metadata-only audited; no tokens are read."}},
		{ID: "t3-code", DisplayName: "T3 Code", Vendor: "T3", Categories: []string{"ai_cli_agent", "ai_coding_agent"}, BinaryNames: []string{"t3-code", "t3"}, ConfigPaths: []string{filepath.Join(home, ".t3"), filepath.Join(home, ".config", "t3")}, ProjectMarkers: []string{".t3", "t3.json"}, RiskNotes: []string{"Generic coding-agent wrapper config should be reviewed for shell/network permissions."}},
		{ID: "replit-agent", DisplayName: "Replit Agent local artifacts", Vendor: "Replit", Categories: []string{"cloud_agent_cli", "ai_coding_agent"}, BinaryNames: []string{"replit"}, ConfigPaths: []string{filepath.Join(home, ".replit"), filepath.Join(home, ".config", "replit")}, ProjectMarkers: []string{".replit", "replit.nix"}, RiskNotes: []string{"Hosted agent local project markers can affect cloud/local workflow context."}},
		{ID: "codeium", DisplayName: "Codeium / Windsurf artifacts", Vendor: "Codeium", Categories: []string{"ai_extension", "cloud_agent_cli"}, BinaryNames: []string{"codeium"}, ConfigPaths: []string{filepath.Join(home, ".codeium"), filepath.Join(home, ".config", "codeium")}, RiskNotes: []string{"Cloud assistant metadata is audited without reading account data."}},
		{ID: "opencode", DisplayName: "OpenCode / opencode", Vendor: "OpenCode", Categories: []string{"ai_cli_agent", "ai_coding_agent", "ai_ide", "mcp_client", "ai_skill_host"}, AppPaths: []string{app("OpenCode.app"), app("opencode.app"), userApp("OpenCode.app")}, BinaryNames: []string{"opencode", "open-code"}, ConfigPaths: []string{filepath.Join(home, ".opencode"), filepath.Join(home, ".config", "opencode"), filepath.Join(home, "Library", "Application Support", "OpenCode"), filepath.Join(home, "Library", "Application Support", "opencode")}, CachePaths: []string{filepath.Join(home, "Library", "Caches", "OpenCode"), filepath.Join(home, "Library", "Caches", "opencode")}, LogPaths: []string{filepath.Join(home, "Library", "Logs", "OpenCode"), filepath.Join(home, "Library", "Logs", "opencode")}, ProjectMarkers: []string{".opencode", "opencode.json", "opencode.yaml", "opencode.yml", "opencode.toml", ".opencode.json", ".opencode.yaml"}, RiskNotes: []string{"Agents, subagents, prompts, rules, skills, provider configs, and MCP tools may influence behavior."}},
		{ID: "hermes-agent", DisplayName: "Hermes Agent", Vendor: "Hermes", Categories: []string{"ai_cli_agent", "agent_orchestrator", "ai_skill_host", "mcp_client", "cloud_agent_cli"}, AppPaths: []string{app("Hermes.app"), app("Hermes Agent.app"), userApp("Hermes.app")}, BinaryNames: []string{"hermes", "hermes-agent"}, ConfigPaths: []string{filepath.Join(home, ".hermes"), filepath.Join(home, ".hermes-agent"), filepath.Join(home, ".config", "hermes"), filepath.Join(home, ".config", "hermes-agent"), filepath.Join(home, "Library", "Application Support", "Hermes"), filepath.Join(home, "Library", "Application Support", "Hermes Agent")}, CachePaths: []string{filepath.Join(home, "Library", "Caches", "Hermes"), filepath.Join(home, "Library", "Caches", "Hermes Agent")}, LogPaths: []string{filepath.Join(home, "Library", "Logs", "Hermes"), filepath.Join(home, "Library", "Logs", "Hermes Agent")}, ProjectMarkers: []string{".hermes", ".hermes-agent", "hermes.json", "hermes.yaml", "hermes.yml", "hermes.toml", "hermes-agent.json", "hermes-agent.yaml"}, RiskNotes: []string{"May combine persistent memory, skills, MCP, remote integrations, and provider configs."}},
		{ID: "sourcegraph-cody", DisplayName: "Sourcegraph Cody", Vendor: "Sourcegraph", Categories: []string{"ai_extension", "cloud_agent_cli"}, BinaryNames: []string{"cody"}, ConfigPaths: []string{filepath.Join(home, ".sourcegraph"), filepath.Join(home, "Library", "Application Support", "Code")}, RiskNotes: []string{"Cloud coding assistant artifacts may include local config metadata."}},
		{ID: "tabnine", DisplayName: "Tabnine", Vendor: "Tabnine", Categories: []string{"ai_extension", "cloud_agent_cli"}, AppPaths: []string{app("Tabnine.app")}, BinaryNames: []string{"tabnine"}, ConfigPaths: []string{filepath.Join(home, ".tabnine")}, RiskNotes: []string{"Completion assistant config is metadata-only audited."}},
		{ID: "jetbrains-ai", DisplayName: "JetBrains AI Assistant", Vendor: "JetBrains", Categories: []string{"ai_ide", "ai_extension"}, AppPaths: []string{app("JetBrains Toolbox.app"), app("IntelliJ IDEA.app"), app("PyCharm.app"), app("WebStorm.app"), app("Android Studio.app")}, ConfigPaths: []string{filepath.Join(home, "Library", "Application Support", "JetBrains")}, RiskNotes: []string{"IDE plugins may access broad project context."}},
		{ID: "zed-ai", DisplayName: "Zed AI", Vendor: "Zed", Categories: []string{"ai_ide", "mcp_client"}, AppPaths: []string{app("Zed.app")}, BinaryNames: []string{"zed"}, ConfigPaths: []string{filepath.Join(home, ".config", "zed"), filepath.Join(home, "Library", "Application Support", "Zed")}, RiskNotes: []string{"Editor AI config may include providers and MCP clients."}},
		{ID: "amazon-q", DisplayName: "Amazon Q Developer", Vendor: "Amazon", Categories: []string{"ai_cli_agent", "ai_extension", "cloud_agent_cli"}, BinaryNames: []string{"q", "amazonq"}, ConfigPaths: []string{filepath.Join(home, ".aws", "amazonq"), filepath.Join(home, ".config", "amazonq")}, RiskNotes: []string{"Cloud agent can interact with AWS context if configured."}},
		{ID: "gemini-cli", DisplayName: "Gemini CLI / Gemini Code Assist", Vendor: "Google", Categories: []string{"ai_cli_agent", "ai_coding_agent", "cloud_agent_cli"}, BinaryNames: []string{"gemini"}, ConfigPaths: []string{filepath.Join(home, ".gemini"), filepath.Join(home, ".gemini", "settings.json"), filepath.Join(home, ".gemini", "skills"), filepath.Join(home, ".config", "gemini")}, ProjectMarkers: []string{"GEMINI.md", filepath.Join(".gemini", "settings.json"), filepath.Join(".gemini", "skills")}, RiskNotes: []string{"Remote model provider usage depends on local provider config and env."}},
		{ID: "ollama", DisplayName: "Ollama", Vendor: "Ollama", Categories: []string{"local_llm_runtime"}, AppPaths: []string{app("Ollama.app")}, BinaryNames: []string{"ollama"}, ConfigPaths: []string{filepath.Join(home, ".ollama"), filepath.Join(home, "Library", "Application Support", "Ollama")}, CachePaths: []string{filepath.Join(home, ".ollama", "models"), filepath.Join(home, ".cache", "ollama")}, Ports: []int{11434}, ProcessNames: []string{"ollama"}, RiskNotes: []string{"Local model API should bind to loopback unless intentionally exposed."}},
		{ID: "lm-studio", DisplayName: "LM Studio", Vendor: "LM Studio", Categories: []string{"local_llm_desktop", "local_llm_runtime"}, AppPaths: []string{app("LM Studio.app")}, ConfigPaths: []string{filepath.Join(home, "Library", "Application Support", "LM Studio")}, CachePaths: []string{filepath.Join(home, "Library", "Caches", "LM Studio"), filepath.Join(home, ".cache", "lm-studio")}, LogPaths: []string{filepath.Join(home, "Library", "Logs", "LM Studio")}, Ports: []int{1234}, ProcessNames: []string{"LM Studio"}, RiskNotes: []string{"Local API exposure and model cache size should be reviewed."}},
		{ID: "jan", DisplayName: "Jan", Vendor: "Jan", Categories: []string{"local_llm_desktop"}, AppPaths: []string{app("Jan.app")}, ConfigPaths: []string{filepath.Join(home, "Library", "Application Support", "Jan")}, Ports: []int{1337}, ProcessNames: []string{"Jan"}, RiskNotes: []string{"Local desktop model app metadata is audited only."}},
		{ID: "gpt4all", DisplayName: "GPT4All", Vendor: "Nomic AI", Categories: []string{"local_llm_desktop"}, AppPaths: []string{app("GPT4All.app")}, ConfigPaths: []string{filepath.Join(home, "Library", "Application Support", "GPT4All")}, RiskNotes: []string{"Model files are not auto-cleaned."}},
		{ID: "anythingllm", DisplayName: "AnythingLLM", Vendor: "Mintplex Labs", Categories: []string{"local_llm_desktop", "local_llm_webui"}, AppPaths: []string{app("AnythingLLM.app")}, ConfigPaths: []string{filepath.Join(home, "Library", "Application Support", "anythingllm-desktop")}, Ports: []int{3001, 8888}, ProcessNames: []string{"AnythingLLM"}, RiskNotes: []string{"Workspace docs and embeddings can contain sensitive context."}},
		{ID: "open-webui", DisplayName: "Open WebUI", Vendor: "Open WebUI", Categories: []string{"local_llm_webui"}, ConfigPaths: []string{filepath.Join(home, ".local", "share", "open-webui"), filepath.Join(home, "Library", "Application Support", "Open WebUI")}, Ports: []int{3000, 8080}, RiskNotes: []string{"Review bindings and auth before exposing local web UI."}},
		{ID: "pinokio", DisplayName: "Pinokio", Vendor: "Pinokio", Categories: []string{"ai_workflow_agent", "local_llm_desktop"}, AppPaths: []string{app("Pinokio.app")}, ConfigPaths: []string{filepath.Join(home, "Library", "Application Support", "Pinokio")}, RiskNotes: []string{"Automation workflows can run local tools if configured."}},
		{ID: "msty", DisplayName: "Msty", Vendor: "Msty", Categories: []string{"local_llm_desktop"}, AppPaths: []string{app("Msty.app")}, ConfigPaths: []string{filepath.Join(home, "Library", "Application Support", "Msty")}, RiskNotes: []string{"Local model/provider config metadata is audited only."}},
		{ID: "boltai", DisplayName: "BoltAI", Vendor: "BoltAI", Categories: []string{"local_llm_desktop", "cloud_agent_cli"}, AppPaths: []string{app("BoltAI.app")}, ConfigPaths: []string{filepath.Join(home, "Library", "Application Support", "BoltAI")}, RiskNotes: []string{"Provider configuration may reference API key env names."}},
		{ID: "mindmac", DisplayName: "MindMac", Vendor: "MindMac", Categories: []string{"local_llm_desktop", "cloud_agent_cli"}, AppPaths: []string{app("MindMac.app")}, ConfigPaths: []string{filepath.Join(home, "Library", "Application Support", "MindMac")}, RiskNotes: []string{"Desktop AI app artifacts are metadata-only audited."}},
		{ID: "sillytavern", DisplayName: "SillyTavern", Vendor: "SillyTavern", Categories: []string{"local_llm_webui"}, ConfigPaths: []string{filepath.Join(home, "Library", "Application Support", "SillyTavern")}, Ports: []int{8000}, RiskNotes: []string{"Local web UI should not be exposed without auth."}},
		{ID: "privategpt", DisplayName: "PrivateGPT", Vendor: "PrivateGPT", Categories: []string{"local_llm_runtime", "local_llm_webui"}, BinaryNames: []string{"privategpt"}, Ports: []int{8000, 8080}, RiskNotes: []string{"Local document stores can contain sensitive context."}},
		{ID: "llama-cpp", DisplayName: "llama.cpp / llama-server", Vendor: "ggml", Categories: []string{"local_llm_runtime"}, BinaryNames: []string{"llama-cli", "llama-server", "llamafile"}, CachePaths: []string{filepath.Join(home, ".cache", "llama.cpp")}, Ports: []int{8000, 8080}, ProcessNames: []string{"llama-server", "llamafile"}, RiskNotes: []string{"Local API binding should be loopback-only."}},
		{ID: "localai", DisplayName: "LocalAI", Vendor: "LocalAI", Categories: []string{"local_llm_runtime", "local_llm_webui"}, BinaryNames: []string{"localai"}, Ports: []int{8080}, ProcessNames: []string{"localai"}, RiskNotes: []string{"Local API can expose model endpoints."}},
		{ID: "vllm", DisplayName: "vLLM", Vendor: "vLLM", Categories: []string{"local_llm_runtime"}, BinaryNames: []string{"vllm"}, Ports: []int{8000}, ProcessNames: []string{"vllm"}, RiskNotes: []string{"Review server binding and auth."}},
		{ID: "text-generation-webui", DisplayName: "text-generation-webui", Vendor: "oobabooga", Categories: []string{"local_llm_webui"}, Ports: []int{7860}, ProcessNames: []string{"text-generation-webui"}, RiskNotes: []string{"Gradio UIs should not bind to non-loopback interfaces without auth."}},
		{ID: "koboldcpp", DisplayName: "koboldcpp", Vendor: "KoboldCpp", Categories: []string{"local_llm_runtime", "local_llm_webui"}, BinaryNames: []string{"koboldcpp"}, Ports: []int{5001}, ProcessNames: []string{"koboldcpp"}, RiskNotes: []string{"Review local API binding."}},
		{ID: "chatgpt-desktop", DisplayName: "ChatGPT Desktop", Vendor: "OpenAI", Categories: []string{"local_llm_desktop", "cloud_agent_cli"}, AppPaths: []string{app("ChatGPT.app")}, ConfigPaths: []string{filepath.Join(home, "Library", "Application Support", "ChatGPT")}, CachePaths: []string{filepath.Join(home, "Library", "Caches", "ChatGPT")}, RiskNotes: []string{"Only local app metadata is audited; chat history content is not read."}},
		{ID: "perplexity-desktop", DisplayName: "Perplexity Desktop", Vendor: "Perplexity", Categories: []string{"local_llm_desktop", "cloud_agent_cli"}, AppPaths: []string{app("Perplexity.app")}, ConfigPaths: []string{filepath.Join(home, "Library", "Application Support", "Perplexity")}, RiskNotes: []string{"Only local app metadata is audited."}},
		{ID: "poe-desktop", DisplayName: "Poe Desktop", Vendor: "Quora", Categories: []string{"local_llm_desktop", "cloud_agent_cli"}, AppPaths: []string{app("Poe.app")}, ConfigPaths: []string{filepath.Join(home, "Library", "Application Support", "Poe")}, RiskNotes: []string{"Only local app metadata is audited."}},
		{ID: "typingmind", DisplayName: "TypingMind", Vendor: "TypingMind", Categories: []string{"local_llm_desktop", "cloud_agent_cli"}, AppPaths: []string{app("TypingMind.app")}, ConfigPaths: []string{filepath.Join(home, "Library", "Application Support", "TypingMind")}, RiskNotes: []string{"Browser-wrapper AI app metadata is audited without reading conversations."}},
		{ID: "lovable-v0-bolt-artifacts", DisplayName: "Lovable / v0 / Bolt workflow artifacts", Vendor: "Various", Categories: []string{"cloud_agent_cli", "ai_workflow_agent"}, ProjectMarkers: []string{"lovable.json", ".lovable", "v0.json", ".v0", "bolt.json", ".bolt"}, RiskNotes: []string{"Project workflow artifacts can guide hosted agents; review before sharing sensitive context."}},
		{ID: "qwen-code", DisplayName: "Qwen Code / Qwen CLI", Vendor: "Alibaba", Categories: []string{"ai_cli_agent", "ai_coding_agent", "cloud_agent_cli"}, BinaryNames: []string{"qwen", "qwen-code", "qwen-cli"}, ConfigPaths: []string{filepath.Join(home, ".qwen"), filepath.Join(home, ".qwen-code"), filepath.Join(home, ".dashscope")}, CachePaths: []string{filepath.Join(home, ".modelscope"), filepath.Join(home, ".cache", "modelscope")}, RiskNotes: []string{"Provider origin is neutral; risk depends on remote API usage and tool permissions."}},
		{ID: "deepseek-cli", DisplayName: "DeepSeek CLI", Vendor: "DeepSeek", Categories: []string{"ai_cli_agent", "cloud_agent_cli"}, BinaryNames: []string{"deepseek", "deepseek-cli"}, ConfigPaths: []string{filepath.Join(home, ".deepseek"), filepath.Join(home, ".config", "deepseek")}, RiskNotes: []string{"Provider origin is neutral; risk depends on remote API usage and tool permissions."}},
		{ID: "kimi-cli", DisplayName: "Kimi CLI", Vendor: "Moonshot AI", Categories: []string{"ai_cli_agent", "cloud_agent_cli"}, BinaryNames: []string{"kimi", "kimi-cli"}, ConfigPaths: []string{filepath.Join(home, ".kimi"), filepath.Join(home, ".moonshot"), filepath.Join(home, ".config", "kimi")}, RiskNotes: []string{"Provider origin is neutral; risk depends on remote API usage and tool permissions."}},
		{ID: "glm-zai-cli", DisplayName: "GLM / Z.ai CLI", Vendor: "Zhipu / Z.ai", Categories: []string{"ai_cli_agent", "cloud_agent_cli"}, BinaryNames: []string{"glm", "zai", "zai-cli"}, ConfigPaths: []string{filepath.Join(home, ".zhipu"), filepath.Join(home, ".zai"), filepath.Join(home, ".glm"), filepath.Join(home, ".bigmodel"), filepath.Join(home, ".codegeex")}, RiskNotes: []string{"Provider origin is neutral; risk depends on remote API usage and tool permissions."}},
		{ID: "doubao-desktop", DisplayName: "Doubao Desktop", Vendor: "ByteDance", Categories: []string{"local_llm_desktop", "cloud_agent_cli"}, AppPaths: []string{app("Doubao.app"), app("豆包.app")}, BinaryNames: []string{"doubao"}, ConfigPaths: []string{filepath.Join(home, "Library", "Application Support", "Doubao"), filepath.Join(home, "Library", "Application Support", "豆包"), filepath.Join(home, ".doubao"), filepath.Join(home, ".ark"), filepath.Join(home, ".volcengine")}, CachePaths: []string{filepath.Join(home, "Library", "Caches", "Doubao")}, RiskNotes: []string{"Provider origin is neutral; app data is metadata-only audited."}},
		{ID: "kimi-desktop", DisplayName: "Kimi Desktop", Vendor: "Moonshot AI", Categories: []string{"local_llm_desktop", "cloud_agent_cli"}, AppPaths: []string{app("Kimi.app")}, ConfigPaths: []string{filepath.Join(home, "Library", "Application Support", "Kimi")}, CachePaths: []string{filepath.Join(home, "Library", "Caches", "Kimi")}, RiskNotes: []string{"Provider origin is neutral; app data is metadata-only audited."}},
		{ID: "qwen-desktop", DisplayName: "Qwen / Tongyi Desktop", Vendor: "Alibaba", Categories: []string{"local_llm_desktop", "cloud_agent_cli"}, AppPaths: []string{app("Qwen.app"), app("通义.app")}, ConfigPaths: []string{filepath.Join(home, "Library", "Application Support", "Qwen"), filepath.Join(home, "Library", "Application Support", "Tongyi"), filepath.Join(home, "Library", "Application Support", "通义")}, CachePaths: []string{filepath.Join(home, "Library", "Caches", "Qwen")}, RiskNotes: []string{"Provider origin is neutral; app data is metadata-only audited."}},
		{ID: "wenxin-desktop", DisplayName: "Wenxin / ERNIE Desktop", Vendor: "Baidu", Categories: []string{"local_llm_desktop", "cloud_agent_cli"}, AppPaths: []string{app("文心一言.app")}, ConfigPaths: []string{filepath.Join(home, "Library", "Application Support", "Wenxin"), filepath.Join(home, "Library", "Application Support", "文心一言")}, RiskNotes: []string{"Provider origin is neutral; app data is metadata-only audited."}},
	}
}

func ChineseProviderDefinitions(home string) []AIModelProviderDefinition {
	return []AIModelProviderDefinition{
		{ID: "qwen", DisplayName: "Alibaba Qwen / Tongyi / DashScope", CountryOrRegion: "China", Vendor: "Alibaba", Families: []string{"qwen", "qwen2", "qwen2.5", "qwen3", "qwen3.5", "qwen-code", "qwen coder", "tongyi", "dashscope", "modelscope"}, APIEnvKeys: []string{"QWEN_API_KEY", "DASHSCOPE_API_KEY", "ALIBABA_CLOUD_ACCESS_KEY_ID", "ALIBABA_CLOUD_ACCESS_KEY_SECRET", "MODELSCOPE_API_TOKEN"}, ConfigPaths: []string{filepath.Join(home, ".qwen"), filepath.Join(home, ".qwen-code"), filepath.Join(home, ".dashscope"), filepath.Join(home, ".modelscope")}, CachePaths: []string{filepath.Join(home, ".cache", "modelscope"), filepath.Join(home, ".cache", "huggingface"), filepath.Join(home, ".cache", "ollama")}, ModelCacheHints: []string{"qwen", "dashscope", "modelscope"}, CLINames: []string{"qwen", "qwen-code", "qwen-cli"}, RiskNotes: []string{"Provider origin alone is not a risk. Review remote API usage and context/tool permissions."}},
		{ID: "deepseek", DisplayName: "DeepSeek", CountryOrRegion: "China", Vendor: "DeepSeek", Families: []string{"deepseek", "deepseek-coder", "deepseek-r1", "deepseek-v3", "deepseek-v4", "deepseek-chat", "deepseek-reasoner"}, APIEnvKeys: []string{"DEEPSEEK_API_KEY", "DEEPSEEK_BASE_URL"}, ConfigPaths: []string{filepath.Join(home, ".deepseek"), filepath.Join(home, ".config", "deepseek")}, CachePaths: []string{filepath.Join(home, ".ollama", "models"), filepath.Join(home, "Library", "Application Support", "LM Studio")}, ModelCacheHints: []string{"deepseek"}, CLINames: []string{"deepseek", "deepseek-cli"}, RiskNotes: []string{"Provider origin alone is not a risk. Review remote API usage and context/tool permissions."}},
		{ID: "kimi", DisplayName: "Moonshot AI / Kimi", CountryOrRegion: "China", Vendor: "Moonshot AI", Families: []string{"kimi", "kimi k2", "moonshot", "moonshot-v1", "kimi-k2", "kimi-latest"}, APIEnvKeys: []string{"MOONSHOT_API_KEY", "KIMI_API_KEY"}, ConfigPaths: []string{filepath.Join(home, ".kimi"), filepath.Join(home, ".moonshot"), filepath.Join(home, ".config", "kimi")}, CachePaths: []string{filepath.Join(home, "Library", "Application Support", "Kimi"), filepath.Join(home, "Library", "Caches", "Kimi")}, ModelCacheHints: []string{"kimi", "moonshot"}, CLINames: []string{"kimi", "kimi-cli"}, RiskNotes: []string{"Provider origin alone is not a risk. Review remote API usage and context/tool permissions."}},
		{ID: "glm-zai", DisplayName: "Zhipu / Z.ai / GLM", CountryOrRegion: "China", Vendor: "Zhipu / Z.ai", Families: []string{"glm", "chatglm", "codegeex", "zhipu", "z.ai", "bigmodel", "glm-4", "glm-4.5", "glm-5", "glm-z1", "glm-coder"}, APIEnvKeys: []string{"ZHIPUAI_API_KEY", "ZAI_API_KEY", "GLM_API_KEY", "BIGMODEL_API_KEY", "CODEGEEX_API_KEY"}, ConfigPaths: []string{filepath.Join(home, ".zhipu"), filepath.Join(home, ".zai"), filepath.Join(home, ".glm"), filepath.Join(home, ".bigmodel"), filepath.Join(home, ".codegeex")}, CachePaths: []string{filepath.Join(home, ".cache", "huggingface"), filepath.Join(home, "Library", "Application Support", "LM Studio")}, ModelCacheHints: []string{"zhipu", "z.ai", "glm", "chatglm", "codegeex"}, CLINames: []string{"glm", "zai", "zai-cli"}, RiskNotes: []string{"Provider origin alone is not a risk. Review remote API usage and context/tool permissions."}},
		{ID: "minimax", DisplayName: "MiniMax", CountryOrRegion: "China", Vendor: "MiniMax", Families: []string{"minimax", "minimax m1", "minimax m2", "abab"}, APIEnvKeys: []string{"MINIMAX_API_KEY", "MINIMAX_GROUP_ID"}, ConfigPaths: []string{filepath.Join(home, ".minimax"), filepath.Join(home, ".config", "minimax")}, CachePaths: []string{filepath.Join(home, ".cache", "huggingface")}, ModelCacheHints: []string{"minimax", "abab"}, CLINames: []string{"minimax"}, RiskNotes: []string{"Provider origin alone is not a risk. Review remote API usage and context/tool permissions."}},
		{ID: "doubao", DisplayName: "ByteDance Doubao / Volcano Engine", CountryOrRegion: "China", Vendor: "ByteDance", Families: []string{"doubao", "豆包", "bytedance", "volcano engine", "ark", "seed", "seed-coder"}, APIEnvKeys: []string{"DOUBAO_API_KEY", "ARK_API_KEY", "VOLCENGINE_ACCESS_KEY", "VOLCENGINE_SECRET_KEY", "BYTEPLUS_API_KEY", "BYTEDANCE_API_KEY"}, ConfigPaths: []string{filepath.Join(home, ".doubao"), filepath.Join(home, ".ark"), filepath.Join(home, ".volcengine"), filepath.Join(home, ".byteplus")}, CachePaths: []string{filepath.Join(home, "Library", "Application Support", "Doubao"), filepath.Join(home, "Library", "Caches", "Doubao")}, ModelCacheHints: []string{"doubao", "ark", "volcengine", "bytedance", "seed-coder"}, CLINames: []string{"doubao"}, RiskNotes: []string{"Provider origin alone is not a risk. Review remote API usage and context/tool permissions."}},
		{ID: "baidu-ernie", DisplayName: "Baidu ERNIE / Wenxin / Qianfan", CountryOrRegion: "China", Vendor: "Baidu", Families: []string{"ernie", "wenxin", "文心", "baidu", "qianfan", "千帆"}, APIEnvKeys: []string{"BAIDU_API_KEY", "BAIDU_SECRET_KEY", "QIANFAN_ACCESS_KEY", "QIANFAN_SECRET_KEY", "WENXIN_API_KEY", "ERNIE_API_KEY"}, ConfigPaths: []string{filepath.Join(home, ".baidu"), filepath.Join(home, ".qianfan"), filepath.Join(home, ".ernie"), filepath.Join(home, ".wenxin")}, CachePaths: []string{filepath.Join(home, "Library", "Application Support", "Wenxin"), filepath.Join(home, "Library", "Application Support", "文心一言")}, ModelCacheHints: []string{"baidu", "ernie", "wenxin", "qianfan"}, CLINames: []string{"ernie", "wenxin"}, RiskNotes: []string{"Provider origin alone is not a risk. Review remote API usage and context/tool permissions."}},
		{ID: "baichuan", DisplayName: "Baichuan", CountryOrRegion: "China", Vendor: "Baichuan", Families: []string{"baichuan", "baichuan2", "baichuan-m2"}, APIEnvKeys: []string{"BAICHUAN_API_KEY"}, ConfigPaths: []string{filepath.Join(home, ".baichuan")}, CachePaths: []string{filepath.Join(home, ".cache", "huggingface")}, ModelCacheHints: []string{"baichuan"}, CLINames: []string{"baichuan"}, RiskNotes: []string{"Provider origin alone is not a risk. Review remote API usage and context/tool permissions."}},
		{ID: "yi", DisplayName: "01.AI / Yi", CountryOrRegion: "China", Vendor: "01.AI", Families: []string{"yi", "yi-coder", "01.ai", "lingyi", "lingyi wanwu", "01-ai"}, APIEnvKeys: []string{"YI_API_KEY", "LINGYI_API_KEY", "ZEROONE_API_KEY"}, ConfigPaths: []string{filepath.Join(home, ".yi"), filepath.Join(home, ".01ai"), filepath.Join(home, ".lingyi")}, CachePaths: []string{filepath.Join(home, ".cache", "huggingface")}, ModelCacheHints: []string{"yi-coder", "01.ai", "lingyi", "01-ai"}, CLINames: []string{"yi"}, RiskNotes: []string{"Provider origin alone is not a risk. Review remote API usage and context/tool permissions."}},
		{ID: "internlm", DisplayName: "Shanghai AI Lab InternLM / InternVL", CountryOrRegion: "China", Vendor: "Shanghai AI Lab", Families: []string{"internlm", "internvl", "opencompass"}, APIEnvKeys: []string{"INTERNLM_API_KEY", "OPENCOMPASS_API_KEY"}, ConfigPaths: []string{filepath.Join(home, ".internlm"), filepath.Join(home, ".opencompass")}, CachePaths: []string{filepath.Join(home, ".cache", "huggingface")}, ModelCacheHints: []string{"internlm", "internvl", "opencompass"}, CLINames: []string{"internlm"}, RiskNotes: []string{"Provider origin alone is not a risk. Review remote API usage and context/tool permissions."}},
		{ID: "hunyuan", DisplayName: "Tencent Hunyuan", CountryOrRegion: "China", Vendor: "Tencent", Families: []string{"hunyuan", "tencentcloud", "hunyuan-lite", "hunyuan-turbo", "hunyuan-large"}, APIEnvKeys: []string{"HUNYUAN_API_KEY", "TENCENTCLOUD_SECRET_ID", "TENCENTCLOUD_SECRET_KEY"}, ConfigPaths: []string{filepath.Join(home, ".hunyuan"), filepath.Join(home, ".tencentcloud")}, CachePaths: []string{filepath.Join(home, ".cache", "huggingface")}, ModelCacheHints: []string{"hunyuan", "tencentcloud"}, CLINames: []string{"hunyuan"}, RiskNotes: []string{"Provider origin alone is not a risk. Review remote API usage and context/tool permissions."}},
		{ID: "stepfun", DisplayName: "StepFun / Step", CountryOrRegion: "China", Vendor: "StepFun", Families: []string{"stepfun", "step", "step-2", "step-3"}, APIEnvKeys: []string{"STEPFUN_API_KEY", "STEP_API_KEY"}, ConfigPaths: []string{filepath.Join(home, ".stepfun"), filepath.Join(home, ".step")}, CachePaths: []string{filepath.Join(home, ".cache", "huggingface")}, ModelCacheHints: []string{"stepfun", "step-"}, CLINames: []string{"stepfun"}, RiskNotes: []string{"Provider origin alone is not a risk. Review remote API usage and context/tool permissions."}},
		{ID: "sensenova", DisplayName: "SenseTime SenseNova", CountryOrRegion: "China", Vendor: "SenseTime", Families: []string{"sensenova", "sensetime", "商汤"}, APIEnvKeys: []string{"SENSENOVA_API_KEY", "SENSETIME_API_KEY"}, ConfigPaths: []string{filepath.Join(home, ".sensenova"), filepath.Join(home, ".sensetime")}, CachePaths: []string{filepath.Join(home, ".cache", "huggingface")}, ModelCacheHints: []string{"sensenova", "sensetime"}, CLINames: []string{"sensenova"}, RiskNotes: []string{"Provider origin alone is not a risk. Review remote API usage and context/tool permissions."}},
	}
}

func detectAIToolCatalog(cfg audit.RuntimeConfig) []audit.AIToolCatalogItem {
	var detected []audit.AIToolCatalogItem
	for _, def := range AIToolDefinitions(cfg.HomeDir) {
		item := detectAIToolDefinition(def, cfg)
		if item.Detected {
			detected = append(detected, item)
		}
	}
	sort.Slice(detected, func(i, j int) bool { return detected[i].DisplayName < detected[j].DisplayName })
	return detected
}

func detectAIToolDefinition(def AIToolDefinition, cfg audit.RuntimeConfig) audit.AIToolCatalogItem {
	item := audit.AIToolCatalogItem{
		ID:             def.ID,
		DisplayName:    def.DisplayName,
		Vendor:         def.Vendor,
		Categories:     append([]string(nil), def.Categories...),
		Ports:          append([]int(nil), def.Ports...),
		ProcessNames:   append([]string(nil), def.ProcessNames...),
		RiskNotes:      append([]string(nil), def.RiskNotes...),
		Recommendation: "Review permissions, context scope, provider configuration, MCP tools, and exposed local servers before using agent mode.",
	}
	item.AppPaths = existingPaths(expandPaths(def.AppPaths, cfg.HomeDir))
	for _, name := range def.BinaryNames {
		if path := findExecutable(name, cfg); path != "" {
			item.BinaryPaths = append(item.BinaryPaths, path)
		}
	}
	item.ConfigPaths = existingPaths(expandPaths(def.ConfigPaths, cfg.HomeDir))
	item.CachePaths = existingPaths(expandPaths(def.CachePaths, cfg.HomeDir))
	item.LogPaths = existingPaths(expandPaths(def.LogPaths, cfg.HomeDir))
	item.ProjectMarkers = existingProjectMarkers(def.ProjectMarkers, cfg)
	for _, path := range append(append([]string{}, item.ConfigPaths...), append(item.CachePaths, item.LogPaths...)...) {
		item.DiskUsageBytes += safePathSize(path, cfg.HomeDir)
	}
	item.Detected = len(item.AppPaths) > 0 || len(item.BinaryPaths) > 0 || len(item.ConfigPaths) > 0 || len(item.CachePaths) > 0 || len(item.LogPaths) > 0 || len(item.ProjectMarkers) > 0
	return item
}

func detectMCPClients(cfg audit.RuntimeConfig) []audit.MCPClientCatalogItem {
	type clientDef struct {
		name  string
		paths []string
	}
	defs := []clientDef{
		{"Claude Desktop", []string{filepath.Join(cfg.HomeDir, "Library", "Application Support", "Claude", "claude_desktop_config.json")}},
		{"Claude Code", []string{filepath.Join(cfg.HomeDir, ".claude"), filepath.Join(cfg.HomeDir, "Library", "Application Support", "Claude Code")}},
		{"ChatGPT Desktop", []string{filepath.Join(cfg.HomeDir, "Library", "Application Support", "ChatGPT")}},
		{"Cursor", []string{filepath.Join(cfg.HomeDir, ".cursor", "mcp.json"), filepath.Join(cfg.HomeDir, "Library", "Application Support", "Cursor", "User", "mcp.json")}},
		{"Windsurf", []string{filepath.Join(cfg.HomeDir, ".windsurf")}},
		{"Cline", []string{filepath.Join(cfg.HomeDir, ".cline")}},
		{"Roo Code", []string{filepath.Join(cfg.HomeDir, ".roo")}},
		{"VS Code", []string{filepath.Join(cfg.HomeDir, "Library", "Application Support", "Code")}},
		{"Continue", []string{filepath.Join(cfg.HomeDir, ".continue", "config.json"), filepath.Join(cfg.HomeDir, ".config", "continue", "config.json")}},
		{"Goose", []string{filepath.Join(cfg.HomeDir, ".goose"), filepath.Join(cfg.HomeDir, ".config", "goose")}},
		{"OpenCode", []string{filepath.Join(cfg.HomeDir, ".opencode"), filepath.Join(cfg.HomeDir, ".config", "opencode")}},
		{"Hermes Agent", []string{filepath.Join(cfg.HomeDir, ".hermes"), filepath.Join(cfg.HomeDir, ".hermes-agent")}},
		{"Google Antigravity", []string{filepath.Join(cfg.HomeDir, ".antigravity"), filepath.Join(cfg.HomeDir, ".gemini", "antigravity"), filepath.Join(cfg.HomeDir, ".gemini", "antigravity", "mcp_config.json"), filepath.Join(cfg.HomeDir, ".gemini", "antigravity-cli"), filepath.Join(cfg.HomeDir, ".gemini", "antigravity-cli", "mcp_config.json")}},
		{"Gemini CLI", []string{filepath.Join(cfg.HomeDir, ".gemini", "settings.json")}},
		{"Zed", []string{filepath.Join(cfg.HomeDir, ".config", "zed"), filepath.Join(cfg.HomeDir, "Library", "Application Support", "Zed")}},
	}
	if cfg.ProjectRoot != "" {
		projectPaths := []string{filepath.Join(cfg.ProjectRoot, ".cursor", "mcp.json"), filepath.Join(cfg.ProjectRoot, ".vscode", "mcp.json"), filepath.Join(cfg.ProjectRoot, ".vscode", "settings.json"), filepath.Join(cfg.ProjectRoot, "mcp.json"), filepath.Join(cfg.ProjectRoot, ".opencode"), filepath.Join(cfg.ProjectRoot, ".hermes"), filepath.Join(cfg.ProjectRoot, ".hermes-agent"), filepath.Join(cfg.ProjectRoot, ".antigravity"), filepath.Join(cfg.ProjectRoot, ".gemini", "settings.json"), filepath.Join(cfg.ProjectRoot, ".agents", "mcp_config.json")}
		defs = append(defs, clientDef{"Project MCP-compatible clients", projectPaths})
	}
	var clients []audit.MCPClientCatalogItem
	for _, def := range defs {
		paths := existingPaths(def.paths)
		if len(paths) == 0 {
			continue
		}
		scope := "user"
		if strings.Contains(strings.Join(paths, "\n"), cfg.ProjectRoot) && cfg.ProjectRoot != "" {
			scope = "project"
		}
		clients = append(clients, audit.MCPClientCatalogItem{Name: def.name, ConfigPaths: paths, Scope: scope, Detected: true, RiskNotes: []string{"MCP client detected from local config metadata; server commands are not executed."}})
	}
	return clients
}

func detectMCPServers(cfg audit.RuntimeConfig) []audit.MCPServerCatalogItem {
	var servers []audit.MCPServerCatalogItem
	for _, path := range candidateMCPCatalogPaths(cfg) {
		for _, parsed := range parseMCPServerCatalog(path, scopeForPath(path, cfg)) {
			category := MCPServerRiskCategory(parsed.ServerName, parsed.Command, parsed.Args)
			severityHint := MCPServerRiskRecommendation(category)
			_, _, dataRisk, commandRisk, networkRisk := ClassifyMCPCommandRisk(parsed.Command, parsed.Args)
			item := audit.MCPServerCatalogItem{
				ServerName:              parsed.ServerName,
				Command:                 safety.RedactSensitiveText(parsed.Command),
				Args:                    redactStringSlice(parsed.Args),
				Transport:               parsed.Transport,
				URL:                     redactURL(parsed.URL),
				EnvKeysOnly:             parsed.EnvKeys,
				ConfigPath:              path,
				Scope:                   parsed.Scope,
				RiskCategory:            category,
				CommandExecutionRisk:    commandRisk || category == "filesystem_shell",
				FilesystemAccessRisk:    category == "filesystem_shell" || containsAnyPattern(strings.ToLower(strings.Join(parsed.Args, " ")), []string{"/", "~", "filesystem", "file-system"}),
				NetworkExfiltrationRisk: networkRisk || parsed.URL != "",
				CredentialAccessRisk:    dataRisk || envKeysIncludeSensitive(parsed.EnvKeys),
				CloudAccessRisk:         category == "cloud_infra" || category == "github_git" || category == "saas_productivity",
				BrowserAutomationRisk:   category == "browser_automation",
				Recommendation:          severityHint,
			}
			servers = append(servers, item)
		}
	}
	sort.Slice(servers, func(i, j int) bool { return servers[i].ServerName < servers[j].ServerName })
	return servers
}

func candidateMCPCatalogPaths(cfg audit.RuntimeConfig) []string {
	paths := candidateMCPPaths(cfg)
	paths = append(paths,
		filepath.Join(cfg.HomeDir, "Library", "Application Support", "Cursor", "User", "mcp.json"),
		filepath.Join(cfg.HomeDir, ".continue", "config.json"),
		filepath.Join(cfg.HomeDir, ".config", "continue", "config.json"),
		filepath.Join(cfg.HomeDir, ".opencode", "mcp.json"),
		filepath.Join(cfg.HomeDir, ".hermes", "mcp.json"),
		filepath.Join(cfg.HomeDir, ".hermes-agent", "mcp.json"),
		filepath.Join(cfg.HomeDir, ".antigravity", "mcp.json"),
		filepath.Join(cfg.HomeDir, ".antigravity", "mcp_config.json"),
		filepath.Join(cfg.HomeDir, ".gemini", "settings.json"),
		filepath.Join(cfg.HomeDir, ".gemini", "mcp.json"),
		filepath.Join(cfg.HomeDir, ".gemini", "mcp.toml"),
		filepath.Join(cfg.HomeDir, ".gemini", "mcp.yaml"),
		filepath.Join(cfg.HomeDir, ".gemini", "antigravity", "mcp_config.json"),
		filepath.Join(cfg.HomeDir, ".gemini", "antigravity", "mcp_config.toml"),
		filepath.Join(cfg.HomeDir, ".gemini", "antigravity", "mcp_config.yaml"),
		filepath.Join(cfg.HomeDir, ".gemini", "antigravity-cli", "mcp_config.json"),
		filepath.Join(cfg.HomeDir, ".gemini", "antigravity-cli", "mcp_config.toml"),
		filepath.Join(cfg.HomeDir, ".gemini", "antigravity-cli", "mcp_config.yaml"),
		filepath.Join(cfg.HomeDir, ".config", "zed", "settings.json"),
	)
	if cfg.ProjectRoot != "" {
		paths = append(paths,
			filepath.Join(cfg.ProjectRoot, ".vscode", "mcp.json"),
			filepath.Join(cfg.ProjectRoot, ".vscode", "settings.json"),
			filepath.Join(cfg.ProjectRoot, ".opencode", "mcp.json"),
			filepath.Join(cfg.ProjectRoot, ".hermes", "mcp.json"),
			filepath.Join(cfg.ProjectRoot, ".hermes-agent", "mcp.json"),
			filepath.Join(cfg.ProjectRoot, ".antigravity", "mcp.json"),
			filepath.Join(cfg.ProjectRoot, ".antigravity", "mcp_config.json"),
			filepath.Join(cfg.ProjectRoot, ".antigravity", "mcp_config.toml"),
			filepath.Join(cfg.ProjectRoot, ".antigravity", "mcp_config.yaml"),
			filepath.Join(cfg.ProjectRoot, ".gemini", "settings.json"),
			filepath.Join(cfg.ProjectRoot, ".gemini", "mcp.json"),
			filepath.Join(cfg.ProjectRoot, ".gemini", "mcp.toml"),
			filepath.Join(cfg.ProjectRoot, ".gemini", "mcp.yaml"),
			filepath.Join(cfg.ProjectRoot, ".agents", "mcp_config.json"),
			filepath.Join(cfg.ProjectRoot, ".agents", "mcp_config.toml"),
			filepath.Join(cfg.ProjectRoot, ".agents", "mcp_config.yaml"),
		)
	}
	return dedupeExistingPaths(paths)
}

func parseMCPServerCatalog(path string, scope string) []parsedMCPServer {
	info, err := os.Stat(path)
	if err != nil || info.IsDir() || info.Size() > 5*1024*1024 {
		return nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var root any
	switch strings.ToLower(filepath.Ext(path)) {
	case ".toml":
		if err := toml.Unmarshal(data, &root); err != nil {
			return nil
		}
	case ".yaml", ".yml":
		if err := yaml.Unmarshal(data, &root); err != nil {
			return nil
		}
	default:
		if err := json.Unmarshal(data, &root); err != nil {
			return nil
		}
	}
	root = normalizeStructuredValue(root)
	var servers []parsedMCPServer
	extractMCPServerMaps(root, "config", path, scope, &servers)
	return servers
}

func extractMCPServerMaps(value any, name string, path string, scope string, out *[]parsedMCPServer) {
	switch x := value.(type) {
	case map[string]any:
		if servers, ok := x["mcpServers"].(map[string]any); ok {
			for serverName, raw := range servers {
				if server, ok := raw.(map[string]any); ok {
					*out = append(*out, mcpServerFromMap(serverName, server, path, scope))
				}
			}
		}
		if servers, ok := x["servers"].(map[string]any); ok {
			for serverName, raw := range servers {
				if server, ok := raw.(map[string]any); ok {
					*out = append(*out, mcpServerFromMap(serverName, server, path, scope))
				}
			}
		}
		if command := stringValue(x["command"]); command != "" {
			*out = append(*out, mcpServerFromMap(name, x, path, scope))
			return
		}
		for k, v := range x {
			if k == "mcpServers" || k == "servers" {
				continue
			}
			extractMCPServerMaps(v, k, path, scope, out)
		}
	case []any:
		for i, item := range x {
			extractMCPServerMaps(item, fmt.Sprintf("%s[%d]", name, i), path, scope, out)
		}
	}
}

func mcpServerFromMap(name string, server map[string]any, path string, scope string) parsedMCPServer {
	return parsedMCPServer{
		ServerName: name,
		Command:    stringValue(server["command"]),
		Args:       stringSliceValue(server["args"]),
		Transport:  firstStringValue(server, []string{"transport", "type"}),
		URL:        firstStringValue(server, []string{"url", "endpoint", "baseUrl", "serverUrl", "httpUrl"}),
		EnvKeys:    envKeysOnly(server["env"]),
		ConfigPath: path,
		Scope:      scope,
	}
}

func firstStringValue(m map[string]any, keys []string) string {
	for _, key := range keys {
		if value := stringValue(m[key]); value != "" {
			return value
		}
	}
	return ""
}

func envKeysOnly(value any) []string {
	var keys []string
	if m, ok := value.(map[string]any); ok {
		for key := range m {
			keys = append(keys, key)
		}
	}
	sort.Strings(keys)
	return keys
}

func MCPServerRiskCategory(serverName string, command string, args []string) string {
	text := strings.ToLower(strings.Join(append([]string{serverName, command}, args...), " "))
	categoryMap := map[string][]string{
		"filesystem_shell":   {"filesystem", "file-system", "shell", "terminal", "command", "exec", "bash", "desktop-commander", "computer-control", "applescript", "osascript"},
		"browser_automation": {"playwright", "puppeteer", "browser", "browserbase", "selenium", "chrome", "chromium"},
		"github_git":         {"github", "gitlab", "bitbucket", " git ", " gh "},
		"cloud_infra":        {"aws", "gcp", "google-cloud", "azure", "kubernetes", "k8s", "docker", "terraform", "pulumi", "vercel", "netlify", "cloudflare", "railway", "fly.io"},
		"database":           {"postgres", "postgresql", "mysql", "sqlite", "mongodb", "redis", "supabase", "neon", "planetscale", "clickhouse", "elasticsearch", "meilisearch", "pinecone", "chroma", "qdrant", "weaviate"},
		"saas_productivity":  {"slack", "notion", "linear", "jira", "confluence", "google-drive", "gmail", "google-calendar", "figma", "airtable", "stripe", "hubspot"},
		"security_tool":      {"snyk", "semgrep", "trivy", "osv", "grype", "zap", "burp", "nuclei"},
	}
	padded := " " + text + " "
	for category, needles := range categoryMap {
		for _, needle := range needles {
			if strings.Contains(padded, needle) {
				return category
			}
		}
	}
	return "unknown"
}

func MCPServerRiskRecommendation(category string) string {
	switch category {
	case "filesystem_shell":
		return "Require explicit approval for filesystem and shell MCP tools; restrict allowed roots and commands."
	case "browser_automation":
		return "Review browser automation scope, downloads, credential exposure, and network access."
	case "github_git", "cloud_infra", "database", "saas_productivity":
		return "Use scoped credentials, least privilege, and explicit approval for state-changing MCP tool calls."
	case "security_tool":
		return "Security scanners can be positive signals, but review tokens and project data shared with them."
	default:
		return "Review MCP server permissions, package pinning, env keys, and transport before enabling."
	}
}

func detectHermesAgent(cfg audit.RuntimeConfig) audit.HermesAgentInfo {
	home := cfg.HomeDir
	info := audit.HermesAgentInfo{
		ConfigPaths: existingPaths([]string{
			filepath.Join(home, ".hermes"), filepath.Join(home, ".hermes-agent"), filepath.Join(home, ".config", "hermes"), filepath.Join(home, ".config", "hermes-agent"),
			filepath.Join(home, "Library", "Application Support", "Hermes"), filepath.Join(home, "Library", "Application Support", "Hermes Agent"),
		}),
		SkillPaths:      existingPaths([]string{filepath.Join(home, ".hermes", "skills"), filepath.Join(home, ".hermes-agent", "skills")}),
		MemoryPaths:     existingPaths([]string{filepath.Join(home, ".hermes", "memory"), filepath.Join(home, ".hermes-agent", "memory")}),
		CommandPaths:    existingPaths([]string{filepath.Join(home, ".hermes", "commands"), filepath.Join(home, ".hermes-agent", "commands")}),
		CacheLogPaths:   existingPaths([]string{filepath.Join(home, "Library", "Caches", "Hermes"), filepath.Join(home, "Library", "Caches", "Hermes Agent"), filepath.Join(home, "Library", "Logs", "Hermes"), filepath.Join(home, "Library", "Logs", "Hermes Agent")}),
		EnvKeysDetected: detectedEnvKeys([]string{"HERMES_API_KEY", "HERMES_TOKEN", "TELEGRAM_BOT_TOKEN", "DISCORD_TOKEN", "SLACK_BOT_TOKEN", "OPENROUTER_API_KEY", "ANTHROPIC_API_KEY", "OPENAI_API_KEY", "OLLAMA_HOST", "VLLM_API_KEY"}),
		Recommendations: []string{"Review Hermes skills, memory, commands, provider configs, and remote integrations before agent mode.", "Never store token values in prompts, memory, or project-local Hermes configs."},
	}
	if cfg.ProjectRoot != "" {
		info.ConfigPaths = append(info.ConfigPaths, existingPaths([]string{filepath.Join(cfg.ProjectRoot, ".hermes"), filepath.Join(cfg.ProjectRoot, ".hermes-agent"), filepath.Join(cfg.ProjectRoot, "hermes.json"), filepath.Join(cfg.ProjectRoot, "hermes.yaml"), filepath.Join(cfg.ProjectRoot, "hermes.yml"), filepath.Join(cfg.ProjectRoot, "hermes.toml"), filepath.Join(cfg.ProjectRoot, "hermes-agent.json"), filepath.Join(cfg.ProjectRoot, "hermes-agent.yaml")})...)
		info.SkillPaths = append(info.SkillPaths, existingPaths([]string{filepath.Join(cfg.ProjectRoot, ".hermes", "skills"), filepath.Join(cfg.ProjectRoot, ".hermes-agent", "skills")})...)
		info.MemoryPaths = append(info.MemoryPaths, existingPaths([]string{filepath.Join(cfg.ProjectRoot, ".hermes", "memory"), filepath.Join(cfg.ProjectRoot, ".hermes-agent", "memory")})...)
		info.CommandPaths = append(info.CommandPaths, existingPaths([]string{filepath.Join(cfg.ProjectRoot, ".hermes", "commands"), filepath.Join(cfg.ProjectRoot, ".hermes-agent", "commands")})...)
	}
	for _, path := range append(append(append([]string{}, info.ConfigPaths...), info.SkillPaths...), append(info.MemoryPaths, append(info.CommandPaths, info.CacheLogPaths...)...)...) {
		info.SizeBytes += safePathSize(path, cfg.HomeDir)
		if meta, err := platform.StatMeta(path); err == nil && (platform.IsWorldWritable(meta.Mode) || platform.IsGroupWritable(meta.Mode)) {
			info.RiskNotes = append(info.RiskNotes, "Writable Hermes artifact: "+path)
		}
	}
	if len(info.EnvKeysDetected) > 0 {
		info.RiskNotes = append(info.RiskNotes, "Hermes-related env key names detected; values are masked.")
	}
	info.Detected = len(info.ConfigPaths) > 0 || len(info.SkillPaths) > 0 || len(info.MemoryPaths) > 0 || len(info.CommandPaths) > 0 || len(info.CacheLogPaths) > 0 || len(info.EnvKeysDetected) > 0
	info.ContextImpact = "none"
	if len(info.SkillPaths) > 0 || len(info.MemoryPaths) > 0 || len(info.CommandPaths) > 0 {
		info.ContextImpact = "high"
	}
	return info
}

func detectOpenCode(cfg audit.RuntimeConfig) audit.OpenCodeInfo {
	home := cfg.HomeDir
	info := audit.OpenCodeInfo{
		AppPaths:        existingPaths([]string{"/Applications/OpenCode.app", "/Applications/opencode.app", filepath.Join(home, "Applications", "OpenCode.app")}),
		ConfigPaths:     existingPaths([]string{filepath.Join(home, ".opencode"), filepath.Join(home, ".config", "opencode"), filepath.Join(home, "Library", "Application Support", "OpenCode"), filepath.Join(home, "Library", "Application Support", "opencode")}),
		AgentPaths:      existingPaths([]string{filepath.Join(home, ".opencode", "agents"), filepath.Join(home, ".opencode", "agent")}),
		PromptRulePaths: existingPaths([]string{filepath.Join(home, ".opencode", "prompts"), filepath.Join(home, ".opencode", "rules"), filepath.Join(home, ".opencode", "skills")}),
		CacheLogPaths:   existingPaths([]string{filepath.Join(home, "Library", "Caches", "OpenCode"), filepath.Join(home, "Library", "Caches", "opencode"), filepath.Join(home, "Library", "Logs", "OpenCode"), filepath.Join(home, "Library", "Logs", "opencode")}),
		EnvKeysDetected: detectedEnvKeys([]string{"OPENCODE_API_KEY", "OPENCODE_PROVIDER", "OPENROUTER_API_KEY", "ANTHROPIC_API_KEY", "OPENAI_API_KEY", "GOOGLE_API_KEY", "GEMINI_API_KEY", "DEEPSEEK_API_KEY", "QWEN_API_KEY", "DASHSCOPE_API_KEY", "MOONSHOT_API_KEY", "KIMI_API_KEY", "ZAI_API_KEY", "GLM_API_KEY"}),
		Recommendations: []string{"Review OpenCode agents, subagents, prompts, rules, skills, MCP configs, and provider settings before using agent mode.", "Use scoped provider keys and require confirmation for shell/network tools."},
	}
	for _, name := range []string{"opencode", "open-code"} {
		if path := findExecutable(name, cfg); path != "" {
			info.BinaryPaths = append(info.BinaryPaths, path)
		}
	}
	if cfg.ProjectRoot != "" {
		info.ConfigPaths = append(info.ConfigPaths, existingPaths([]string{filepath.Join(cfg.ProjectRoot, ".opencode"), filepath.Join(cfg.ProjectRoot, "opencode.json"), filepath.Join(cfg.ProjectRoot, "opencode.yaml"), filepath.Join(cfg.ProjectRoot, "opencode.yml"), filepath.Join(cfg.ProjectRoot, "opencode.toml"), filepath.Join(cfg.ProjectRoot, ".opencode.json"), filepath.Join(cfg.ProjectRoot, ".opencode.yaml")})...)
		info.AgentPaths = append(info.AgentPaths, existingPaths([]string{filepath.Join(cfg.ProjectRoot, ".opencode", "agents"), filepath.Join(cfg.ProjectRoot, ".opencode", "agent")})...)
		info.PromptRulePaths = append(info.PromptRulePaths, existingPaths([]string{filepath.Join(cfg.ProjectRoot, ".opencode", "prompts"), filepath.Join(cfg.ProjectRoot, ".opencode", "rules"), filepath.Join(cfg.ProjectRoot, ".opencode", "skills")})...)
	}
	for _, path := range append(append(append([]string{}, info.AppPaths...), append(info.BinaryPaths, info.ConfigPaths...)...), append(info.AgentPaths, append(info.PromptRulePaths, info.CacheLogPaths...)...)...) {
		info.SizeBytes += safePathSize(path, cfg.HomeDir)
		if meta, err := platform.StatMeta(path); err == nil && (platform.IsWorldWritable(meta.Mode) || platform.IsGroupWritable(meta.Mode)) {
			info.RiskNotes = append(info.RiskNotes, "Writable OpenCode artifact: "+path)
		}
	}
	if len(info.EnvKeysDetected) > 0 {
		info.RiskNotes = append(info.RiskNotes, "OpenCode/provider env key names detected; values are masked.")
	}
	info.Detected = len(info.AppPaths) > 0 || len(info.BinaryPaths) > 0 || len(info.ConfigPaths) > 0 || len(info.AgentPaths) > 0 || len(info.PromptRulePaths) > 0 || len(info.CacheLogPaths) > 0 || len(info.EnvKeysDetected) > 0
	info.ContextImpact = "none"
	if len(info.AgentPaths) > 0 || len(info.PromptRulePaths) > 0 || len(info.ConfigPaths) > 0 {
		info.ContextImpact = "high"
	}
	return info
}

func detectChineseAIProviders(cfg audit.RuntimeConfig) []audit.ChineseAIProviderInfo {
	var providers []audit.ChineseAIProviderInfo
	projectMentions := map[string][]string{}
	if cfg.Deep && cfg.ProjectRoot != "" {
		projectMentions = scanProjectForProviderMentions(cfg)
	}
	for _, def := range ChineseProviderDefinitions(cfg.HomeDir) {
		info := audit.ChineseAIProviderInfo{
			ID:              def.ID,
			DisplayName:     def.DisplayName,
			CountryOrRegion: def.CountryOrRegion,
			Vendor:          def.Vendor,
			Families:        append([]string(nil), def.Families...),
			ModelCacheHints: append([]string(nil), def.ModelCacheHints...),
			RiskNotes:       append([]string(nil), def.RiskNotes...),
			Recommendation:  "Provider origin is not a risk by itself. Review remote API usage, context sharing, token exposure, unsafe agent permissions, logs/caches, and exposed local servers.",
		}
		info.EnvKeysDetected = detectedEnvKeys(def.APIEnvKeys)
		info.ConfigPaths = existingPaths(def.ConfigPaths)
		info.CachePaths = existingProviderCachePaths(def.CachePaths, def.ModelCacheHints, cfg.HomeDir)
		for _, cli := range def.CLINames {
			if path := findExecutable(cli, cfg); path != "" {
				info.CLINamesDetected = append(info.CLINamesDetected, cli+"="+path)
			}
		}
		info.ProjectMentions = projectMentions[def.ID]
		for _, path := range append([]string{}, info.CachePaths...) {
			info.LocalCacheSizeBytes += safePathSize(path, cfg.HomeDir)
		}
		info.RemoteEndpointHint = len(info.EnvKeysDetected) > 0 || hasBaseURLEnv(def.APIEnvKeys)
		info.Detected = len(info.EnvKeysDetected) > 0 || len(info.ConfigPaths) > 0 || len(info.CachePaths) > 0 || len(info.CLINamesDetected) > 0 || len(info.ProjectMentions) > 0
		info.RiskLevel = ClassifyProviderUsageRisk(false, len(info.EnvKeysDetected) > 0, false, false, false)
		if info.Detected {
			providers = append(providers, info)
		}
	}
	sort.Slice(providers, func(i, j int) bool { return providers[i].DisplayName < providers[j].DisplayName })
	return providers
}

func scanProjectForProviderMentions(cfg audit.RuntimeConfig) map[string][]string {
	result := map[string][]string{}
	defs := ChineseProviderDefinitions(cfg.HomeDir)
	walkLimited(cfg.ProjectRoot, cfg.HomeDir, func(path string, d os.DirEntry) {
		if d.IsDir() || !shouldScanPromptFile(path) {
			return
		}
		info, err := d.Info()
		if err != nil || info.Size() > int64(cfg.MaxFileSizeMB)*1024*1024 {
			return
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return
		}
		lower := strings.ToLower(string(data))
		for _, def := range defs {
			for _, hint := range def.ModelCacheHints {
				if strings.Contains(lower, strings.ToLower(hint)) {
					result[def.ID] = append(result[def.ID], path+" mentions "+hint)
					break
				}
			}
		}
	})
	return result
}

func ClassifyProviderUsageRisk(originOnly bool, hasAPIKeyEnv bool, broadToolAccess bool, shellAccess bool, mcpAccess bool) string {
	if originOnly && !hasAPIKeyEnv && !broadToolAccess && !shellAccess && !mcpAccess {
		return "info"
	}
	if hasAPIKeyEnv && (broadToolAccess || shellAccess || mcpAccess) {
		return "high"
	}
	if broadToolAccess || shellAccess || mcpAccess {
		return "medium"
	}
	if hasAPIKeyEnv {
		return "medium"
	}
	return "info"
}

func detectLocalModelInventory(cfg audit.RuntimeConfig, providers []audit.ChineseAIProviderInfo) []audit.LocalModelInventoryItem {
	candidates := []struct {
		tool string
		path string
	}{
		{"Ollama", filepath.Join(cfg.HomeDir, ".ollama", "models")},
		{"Ollama", filepath.Join(cfg.HomeDir, "Library", "Application Support", "Ollama")},
		{"LM Studio", filepath.Join(cfg.HomeDir, "Library", "Application Support", "LM Studio")},
		{"Jan", filepath.Join(cfg.HomeDir, "Library", "Application Support", "Jan")},
		{"GPT4All", filepath.Join(cfg.HomeDir, "Library", "Application Support", "GPT4All")},
		{"AnythingLLM", filepath.Join(cfg.HomeDir, "Library", "Application Support", "anythingllm-desktop")},
		{"Open WebUI", filepath.Join(cfg.HomeDir, ".local", "share", "open-webui")},
		{"Open WebUI", filepath.Join(cfg.HomeDir, "Library", "Application Support", "Open WebUI")},
		{"Pinokio", filepath.Join(cfg.HomeDir, "Library", "Application Support", "Pinokio")},
		{"Msty", filepath.Join(cfg.HomeDir, "Library", "Application Support", "Msty")},
		{"SillyTavern", filepath.Join(cfg.HomeDir, "Library", "Application Support", "SillyTavern")},
		{"PrivateGPT", filepath.Join(cfg.HomeDir, "Library", "Application Support", "PrivateGPT")},
		{"Hugging Face", filepath.Join(cfg.HomeDir, ".cache", "huggingface")},
		{"ModelScope", filepath.Join(cfg.HomeDir, ".cache", "modelscope")},
		{"Torch", filepath.Join(cfg.HomeDir, ".cache", "torch")},
		{"llama.cpp", filepath.Join(cfg.HomeDir, ".cache", "llama.cpp")},
		{"Whisper", filepath.Join(cfg.HomeDir, ".cache", "whisper")},
		{"ExLlama", filepath.Join(cfg.HomeDir, ".cache", "exllama")},
		{"MLX", filepath.Join(cfg.HomeDir, ".cache", "mlx")},
		{"llama-cpp-python", filepath.Join(cfg.HomeDir, ".cache", "llama-cpp-python")},
	}
	var items []audit.LocalModelInventoryItem
	for _, candidate := range candidates {
		meta, err := platform.StatMeta(candidate.path)
		if err != nil {
			continue
		}
		stats := aiDirectoryStats(candidate.path, cfg.HomeDir)
		items = append(items, audit.LocalModelInventoryItem{
			ToolName:        candidate.tool,
			ProviderHint:    providerHintForPath(candidate.path, providers),
			Path:            candidate.path,
			SizeBytes:       stats.SizeBytes,
			HumanSize:       platform.HumanBytes(stats.SizeBytes),
			FileCount:       stats.FileCount,
			LastModified:    meta.ModTime.Format("2006-01-02T15:04:05"),
			SafeToAutoClean: false,
			Recommendation:  "Manual review only. Local model/cache files can be large but are never auto-cleaned by this tool.",
		})
	}
	sort.Slice(items, func(i, j int) bool { return items[i].SizeBytes > items[j].SizeBytes })
	return items
}

func detectAISecurityTools(cfg audit.RuntimeConfig) []audit.AISecurityToolCatalogItem {
	patterns := []struct {
		name  string
		paths []string
	}{
		{"Snyk Agent Scan", []string{filepath.Join(cfg.ProjectRoot, "snyk-agent-scan.yaml"), filepath.Join(cfg.ProjectRoot, "snyk-agent-scan.yml"), filepath.Join(cfg.ProjectRoot, ".snyk")}},
		{"Cisco MCP Scanner", []string{filepath.Join(cfg.ProjectRoot, "cisco-mcp-scan.yaml"), filepath.Join(cfg.ProjectRoot, "cisco-mcp-scanner.yaml"), filepath.Join(cfg.ProjectRoot, "ai-defense-mcp-scan.yaml")}},
		{"Promptfoo", []string{filepath.Join(cfg.ProjectRoot, "promptfoo.yaml"), filepath.Join(cfg.ProjectRoot, "promptfooconfig.yaml")}},
		{"Garak", []string{filepath.Join(cfg.ProjectRoot, "garak.yaml"), filepath.Join(cfg.ProjectRoot, "garak.yml")}},
		{"PyRIT", []string{filepath.Join(cfg.ProjectRoot, "pyrit.yaml"), filepath.Join(cfg.ProjectRoot, "pyrit.yml")}},
		{"Giskard", []string{filepath.Join(cfg.ProjectRoot, "giskard.yaml"), filepath.Join(cfg.ProjectRoot, "giskard.yml")}},
		{"DeepTeam", []string{filepath.Join(cfg.ProjectRoot, "deepteam.yaml"), filepath.Join(cfg.ProjectRoot, "deepteam.yml")}},
		{"Lakera Guard", []string{filepath.Join(cfg.ProjectRoot, "lakera.yaml"), filepath.Join(cfg.ProjectRoot, "lakera.yml")}},
		{"Protect AI", []string{filepath.Join(cfg.ProjectRoot, "protectai.yaml"), filepath.Join(cfg.ProjectRoot, "protectai.yml")}},
		{"Langfuse", []string{filepath.Join(cfg.ProjectRoot, "langfuse.json"), filepath.Join(cfg.ProjectRoot, "langfuse.yaml")}},
		{"LangSmith", []string{filepath.Join(cfg.ProjectRoot, "langsmith.json"), filepath.Join(cfg.ProjectRoot, "langsmith.yaml")}},
		{"Helicone", []string{filepath.Join(cfg.ProjectRoot, "helicone.json"), filepath.Join(cfg.ProjectRoot, "helicone.yaml")}},
		{"OpenTelemetry AI traces", []string{filepath.Join(cfg.ProjectRoot, "otel.yaml"), filepath.Join(cfg.ProjectRoot, "opentelemetry.yaml")}},
		{"Semgrep", []string{filepath.Join(cfg.ProjectRoot, "semgrep.yml"), filepath.Join(cfg.ProjectRoot, ".semgrep")}},
		{"Snyk", []string{filepath.Join(cfg.ProjectRoot, ".snyk")}},
		{"mcp-scan", []string{filepath.Join(cfg.ProjectRoot, "mcp-scan.json"), filepath.Join(cfg.ProjectRoot, "mcp-scan.yaml")}},
	}
	var tools []audit.AISecurityToolCatalogItem
	for _, pattern := range patterns {
		paths := existingPaths(pattern.paths)
		if len(paths) > 0 {
			tools = append(tools, audit.AISecurityToolCatalogItem{Name: pattern.name, Detected: true, Paths: paths, PositiveSignal: true, RiskNotes: []string{"Security tool config detected. This is a positive signal unless token values are embedded; token values are not read."}})
		}
	}
	if cfg.ProjectRoot != "" {
		workflowMatches, _ := filepath.Glob(filepath.Join(cfg.ProjectRoot, ".github", "workflows", "*"))
		for _, path := range workflowMatches {
			base := strings.ToLower(filepath.Base(path))
			if strings.Contains(base, "mcp") || strings.Contains(base, "agent") || strings.Contains(base, "snyk") || strings.Contains(base, "semgrep") {
				tools = append(tools, audit.AISecurityToolCatalogItem{Name: "GitHub Actions AI/security workflow", Detected: true, Paths: []string{path}, PositiveSignal: true, RiskNotes: []string{"Workflow name suggests AI/security scanning. Review config metadata; token values are not read."}})
			}
		}
	}
	return tools
}

func aiToolCatalogFindings(tools []audit.AIToolCatalogItem, clients []audit.MCPClientCatalogItem, servers []audit.MCPServerCatalogItem, hermes audit.HermesAgentInfo, opencode audit.OpenCodeInfo, providers []audit.ChineseAIProviderInfo, models []audit.LocalModelInventoryItem, securityTools []audit.AISecurityToolCatalogItem) []audit.Finding {
	var findings []audit.Finding
	findings = append(findings, newFinding("ai-tool-catalog-summary", audit.CategoryAISecurity, "AI Tool Catalog summary", audit.StatusInfo, audit.SeverityInfo, fmt.Sprintf("tools=%d mcp_clients=%d mcp_servers=%d providers=%d local_model_paths=%d security_tools=%d", len(tools), len(clients), len(servers), len(providers), len(models), len(securityTools)), "Tool detection is not a risk verdict. Review permissions, context, shell access, remote provider usage, and exposed servers.", ""))
	if hermes.Detected {
		f := newFinding("ai-hermes-agent-detected", audit.CategoryAISecurity, "Hermes Agent detected", audit.StatusWarn, audit.SeverityMedium, fmt.Sprintf("configs=%d skills=%d memory=%d commands=%d env_keys=%s size=%s", len(hermes.ConfigPaths), len(hermes.SkillPaths), len(hermes.MemoryPaths), len(hermes.CommandPaths), strings.Join(hermes.EnvKeysDetected, ","), platform.HumanBytes(hermes.SizeBytes)), "Review Hermes skills, memory, commands, remote integrations, and provider env key names before using agent mode.", "")
		f.Subtype = "Hermes Agent"
		f.ContextImpact = hermes.ContextImpact
		f.DataExposureRisk = len(hermes.EnvKeysDetected) > 0
		findings = append(findings, f)
	}
	if opencode.Detected {
		f := newFinding("ai-opencode-detected", audit.CategoryAISecurity, "OpenCode/opencode detected", audit.StatusWarn, audit.SeverityMedium, fmt.Sprintf("apps=%d binaries=%d configs=%d agents=%d prompts_rules=%d env_keys=%s size=%s", len(opencode.AppPaths), len(opencode.BinaryPaths), len(opencode.ConfigPaths), len(opencode.AgentPaths), len(opencode.PromptRulePaths), strings.Join(opencode.EnvKeysDetected, ","), platform.HumanBytes(opencode.SizeBytes)), "Review OpenCode agents/subagents, prompts, rules, skills, MCP configs, provider settings, and tool permissions.", "")
		f.Subtype = "OpenCode"
		f.ContextImpact = opencode.ContextImpact
		f.DataExposureRisk = len(opencode.EnvKeysDetected) > 0
		findings = append(findings, f)
	}
	for _, server := range servers {
		if !(server.CommandExecutionRisk || server.FilesystemAccessRisk || server.NetworkExfiltrationRisk || server.CredentialAccessRisk || server.CloudAccessRisk || server.BrowserAutomationRisk) {
			continue
		}
		f := newFinding("ai-mcp-server-risk-"+safeID(server.ConfigPath+"-"+server.ServerName), audit.CategoryAISecurity, "Configured MCP server risk: "+server.ServerName, audit.StatusWarn, audit.SeverityHigh, fmt.Sprintf("config=%s scope=%s category=%s command=%s env_keys=%s url=%s", server.ConfigPath, server.Scope, server.RiskCategory, server.Command, strings.Join(server.EnvKeysOnly, ","), server.URL), server.Recommendation, "")
		f.Subtype = "MCP Server"
		f.CommandExecutionRisk = server.CommandExecutionRisk
		f.DataExposureRisk = server.CredentialAccessRisk || server.FilesystemAccessRisk
		f.NetworkExfiltrationRisk = server.NetworkExfiltrationRisk || server.CloudAccessRisk
		findings = append(findings, f)
	}
	for _, provider := range providers {
		if len(provider.EnvKeysDetected) == 0 && !provider.RemoteEndpointHint {
			continue
		}
		severity := audit.SeverityMedium
		if provider.RiskLevel == "high" {
			severity = audit.SeverityHigh
		}
		f := newFinding("ai-provider-"+provider.ID, audit.CategoryAISecurity, provider.DisplayName+" provider artifacts detected", audit.StatusWarn, severity, fmt.Sprintf("env_keys=%s configs=%d caches=%d project_mentions=%d cache_size=%s risk_basis=%s", strings.Join(provider.EnvKeysDetected, ","), len(provider.ConfigPaths), len(provider.CachePaths), len(provider.ProjectMentions), platform.HumanBytes(provider.LocalCacheSizeBytes), provider.RiskLevel), provider.Recommendation, "")
		f.Subtype = "Chinese AI Models & Providers"
		f.DataExposureRisk = len(provider.EnvKeysDetected) > 0
		findings = append(findings, f)
	}
	for _, model := range models {
		if model.SizeBytes < 5*1024*1024*1024 {
			continue
		}
		f := newFinding("ai-local-model-cache-"+safeID(model.Path), audit.CategoryStorage, "Local AI model/cache directory consumes significant disk space", audit.StatusInfo, audit.SeverityInfo, fmt.Sprintf("tool=%s provider_hint=%s path=%s size=%s files=%d", model.ToolName, model.ProviderHint, model.Path, model.HumanSize, model.FileCount), model.Recommendation, "")
		f.Subtype = "Local Model Inventory"
		f.EstimatedSizeBytes = model.SizeBytes
		findings = append(findings, f)
	}
	return findings
}

func calculateAIProviderSummary(ctx context.Context, runner *platform.Runner, tools []audit.AIToolCatalogItem, clients []audit.MCPClientCatalogItem, servers []audit.MCPServerCatalogItem, hermes audit.HermesAgentInfo, opencode audit.OpenCodeInfo, providers []audit.ChineseAIProviderInfo, models []audit.LocalModelInventoryItem) audit.AIProviderSummary {
	var summary audit.AIProviderSummary
	summary.TotalAIToolsDetected = len(tools)
	summary.TotalMCPClientsDetected = len(clients)
	summary.TotalMCPServersDetected = len(servers)
	summary.HermesDetected = hermes.Detected
	summary.OpenCodeDetected = opencode.Detected
	summary.ChineseProvidersDetected = len(providers)
	for _, provider := range providers {
		summary.RemoteProviderEnvKeysDetected += len(provider.EnvKeysDetected)
	}
	for _, model := range models {
		summary.LocalModelCacheSizeBytes += model.SizeBytes
	}
	for _, server := range inspectCatalogListeningServers(ctx, runner) {
		if server.Risk == "external" {
			summary.NonLoopbackAIServers++
		}
	}
	return summary
}

func inspectCatalogListeningServers(ctx context.Context, runner *platform.Runner) []audit.LocalServerInfo {
	commonPorts := []string{":11434", ":1234", ":3000", ":5000", ":5001", ":7860", ":8000", ":8080", ":8188", ":8501", ":8888", ":9090"}
	var servers []audit.LocalServerInfo
	lsof := runner.Run(ctx, "lsof", "-nP", "-iTCP", "-sTCP:LISTEN")
	for _, line := range strings.Split(lsof.Output, "\n") {
		lower := strings.ToLower(line)
		matches := false
		for _, port := range commonPorts {
			if strings.Contains(lower, port) {
				matches = true
				break
			}
		}
		if !matches {
			continue
		}
		if server, ok := parseListeningLine(line); ok {
			servers = append(servers, server)
		}
	}
	return servers
}

func existingPaths(paths []string) []string {
	var out []string
	for _, path := range paths {
		if path == "" {
			continue
		}
		if _, err := os.Stat(path); err == nil {
			out = append(out, path)
		}
	}
	return out
}

func expandPaths(paths []string, home string) []string {
	out := make([]string, 0, len(paths))
	for _, path := range paths {
		out = append(out, platform.ExpandHome(path, home))
	}
	return out
}

func existingProjectMarkers(markers []string, cfg audit.RuntimeConfig) []string {
	if cfg.ProjectRoot == "" {
		return nil
	}
	var out []string
	for _, marker := range markers {
		path := filepath.Join(cfg.ProjectRoot, marker)
		if _, err := os.Stat(path); err == nil {
			out = append(out, path)
		}
	}
	return out
}

func safePathSize(path string, home string) int64 {
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSymlink != 0 {
		return 0
	}
	if !info.IsDir() {
		return info.Size()
	}
	size, err := platform.DirectorySize(path, home)
	if err != nil {
		return 0
	}
	return size
}

func dedupeExistingPaths(paths []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, path := range existingPaths(paths) {
		if seen[path] {
			continue
		}
		seen[path] = true
		out = append(out, path)
	}
	sort.Strings(out)
	return out
}

func scopeForPath(path string, cfg audit.RuntimeConfig) string {
	if cfg.ProjectRoot != "" {
		if rel, err := filepath.Rel(cfg.ProjectRoot, path); err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			return "project"
		}
	}
	if strings.HasPrefix(path, "/Library") || strings.HasPrefix(path, "/Applications") {
		return "global"
	}
	return "user"
}

func redactStringSlice(values []string) []string {
	out := make([]string, len(values))
	for i, value := range values {
		out[i] = safety.RedactSensitiveText(value)
	}
	return out
}

func redactURL(value string) string {
	if value == "" {
		return ""
	}
	return safety.RedactSensitiveText(value)
}

func envKeysIncludeSensitive(keys []string) bool {
	for _, key := range keys {
		if safety.IsSensitiveEnvName(key) {
			return true
		}
	}
	return false
}

func detectedEnvKeys(keys []string) []string {
	var detected []string
	for _, key := range keys {
		if _, ok := os.LookupEnv(key); ok {
			detected = append(detected, key+"=***MASKED***")
		}
	}
	sort.Strings(detected)
	return detected
}

func hasBaseURLEnv(keys []string) bool {
	for _, key := range keys {
		if strings.Contains(strings.ToUpper(key), "BASE_URL") {
			if _, ok := os.LookupEnv(key); ok {
				return true
			}
		}
	}
	return false
}

func existingProviderCachePaths(paths []string, hints []string, home string) []string {
	var out []string
	for _, path := range existingPaths(paths) {
		if filepath.Base(path) == "huggingface" || filepath.Base(path) == "modelscope" || filepath.Base(path) == "models" || filepath.Base(path) == "ollama" {
			if containsHintInTreeName(path, hints, home) {
				out = append(out, path)
			}
			continue
		}
		out = append(out, path)
	}
	return out
}

func containsHintInTreeName(root string, hints []string, home string) bool {
	found := false
	walkLimited(root, home, func(path string, d os.DirEntry) {
		if found {
			return
		}
		lower := strings.ToLower(path)
		for _, hint := range hints {
			if strings.Contains(lower, strings.ToLower(hint)) {
				found = true
				return
			}
		}
	})
	return found
}

func providerHintForPath(path string, providers []audit.ChineseAIProviderInfo) string {
	lower := strings.ToLower(path)
	for _, provider := range providers {
		for _, hint := range provider.ModelCacheHints {
			if strings.Contains(lower, strings.ToLower(hint)) {
				return provider.DisplayName
			}
		}
	}
	return ""
}
