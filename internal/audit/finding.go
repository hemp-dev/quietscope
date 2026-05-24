package audit

import "time"

type Status string
type Severity string
type Category string

const (
	StatusPass    Status = "PASS"
	StatusWarn    Status = "WARN"
	StatusFail    Status = "FAIL"
	StatusInfo    Status = "INFO"
	StatusSkipped Status = "SKIPPED"
)

const (
	SeverityInfo     Severity = "info"
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

const (
	CategorySystem      Category = "system"
	CategorySecurity    Category = "security"
	CategoryPrivacy     Category = "privacy"
	CategoryUpdates     Category = "updates"
	CategoryPersistence Category = "persistence"
	CategoryPermissions Category = "permissions"
	CategoryStorage     Category = "storage"
	CategoryCleanup     Category = "cleanup"
	CategoryPerformance Category = "performance"
	CategoryAISecurity  Category = "ai_security"
	CategorySecrets     Category = "secrets"
	CategoryReporting   Category = "reporting"
)

type Finding struct {
	ID                      string   `json:"id"`
	Category                Category `json:"category"`
	Title                   string   `json:"title"`
	Status                  Status   `json:"status"`
	Severity                Severity `json:"severity"`
	Evidence                string   `json:"evidence"`
	Recommendation          string   `json:"recommendation"`
	CommandChecked          string   `json:"command_checked"`
	SafeToAutoFix           bool     `json:"safe_to_auto_fix"`
	CleanupCandidate        bool     `json:"cleanup_candidate"`
	EstimatedSizeBytes      int64    `json:"estimated_size_bytes"`
	DataExposureRisk        bool     `json:"data_exposure_risk"`
	CommandExecutionRisk    bool     `json:"command_execution_risk"`
	NetworkExfiltrationRisk bool     `json:"network_exfiltration_risk"`
	Subtype                 string   `json:"subtype,omitempty"`
	ContextImpact           string   `json:"context_impact,omitempty"`
	ContextImpactScore      int      `json:"context_impact_score,omitempty"`
}

type CleanupCandidate struct {
	Path               string `json:"path"`
	Reason             string `json:"reason"`
	Risk               string `json:"risk"`
	EstimatedSizeBytes int64  `json:"estimated_size_bytes"`
	SafeToAutoFix      bool   `json:"safe_to_auto_fix"`
	FindingID          string `json:"finding_id,omitempty"`
}

type AIToolInfo struct {
	Name     string `json:"name"`
	Kind     string `json:"kind"`
	Path     string `json:"path"`
	Detected bool   `json:"detected"`
}

type MCPConfigInfo struct {
	Path        string `json:"path"`
	ServerName  string `json:"server_name,omitempty"`
	Command     string `json:"command,omitempty"`
	Permission  string `json:"permission,omitempty"`
	Risk        string `json:"risk"`
	Description string `json:"description"`
}

type LocalServerInfo struct {
	Name    string `json:"name"`
	PID     string `json:"pid,omitempty"`
	Address string `json:"address"`
	Port    string `json:"port"`
	Risk    string `json:"risk"`
}

type PromptArtifact struct {
	Path     string   `json:"path"`
	Line     int      `json:"line"`
	Phrase   string   `json:"phrase"`
	Severity Severity `json:"severity"`
}

type AISecuritySummary struct {
	InstalledTools  []AIToolInfo      `json:"installed_tools"`
	MCPConfigs      []MCPConfigInfo   `json:"mcp_configs"`
	LocalServers    []LocalServerInfo `json:"local_servers"`
	PromptArtifacts []PromptArtifact  `json:"prompt_artifacts"`
	Recommendations []string          `json:"recommendations"`
}

type AIContextArtifact struct {
	Path                                string             `json:"path"`
	ArtifactType                        string             `json:"artifact_type"`
	ToolName                            string             `json:"tool_name"`
	Scope                               string             `json:"scope"`
	SizeBytes                           int64              `json:"size_bytes"`
	FileCount                           int                `json:"file_count,omitempty"`
	LastModified                        string             `json:"last_modified"`
	Owner                               string             `json:"owner"`
	Permissions                         string             `json:"permissions"`
	IsWorldWritable                     bool               `json:"is_world_writable"`
	IsGroupWritable                     bool               `json:"is_group_writable"`
	IsHidden                            bool               `json:"is_hidden"`
	IsProjectLocal                      bool               `json:"is_project_local"`
	AutoLoadedLikelihood                string             `json:"auto_loaded_likelihood"`
	ContextImpact                       string             `json:"context_impact"`
	ContextImpactScore                  int                `json:"context_impact_score"`
	ContainsSuspiciousPromptPatterns    bool               `json:"contains_suspicious_prompt_patterns"`
	ContainsToolExecutionPatterns       bool               `json:"contains_tool_execution_patterns"`
	ContainsNetworkExfiltrationPatterns bool               `json:"contains_network_exfiltration_patterns"`
	Recommendation                      string             `json:"recommendation"`
	SuspiciousPatterns                  []AIContextPattern `json:"suspicious_patterns,omitempty"`
}

type AIContextPattern struct {
	Pattern string `json:"pattern"`
	Line    int    `json:"line"`
	Snippet string `json:"snippet"`
}

type AIRelatedDirectory struct {
	Path               string `json:"path"`
	ToolName           string `json:"tool_name"`
	Category           string `json:"category"`
	SizeBytes          int64  `json:"size_bytes"`
	HumanSize          string `json:"human_size"`
	FileCount          int    `json:"file_count"`
	LastModified       string `json:"last_modified"`
	Permissions        string `json:"permissions"`
	ContextImpact      string `json:"context_impact"`
	ContextImpactScore int    `json:"context_impact_score"`
	CleanupCandidate   bool   `json:"cleanup_candidate"`
	SafeToAutoClean    bool   `json:"safe_to_auto_clean"`
	Recommendation     string `json:"recommendation"`
}

type AIContextSummary struct {
	TotalAIDirectories              int   `json:"total_ai_directories"`
	TotalAIDirectorySizeBytes       int64 `json:"total_ai_directory_size_bytes"`
	TotalAIContextArtifacts         int   `json:"total_ai_context_artifacts"`
	CriticalContextImpactCount      int   `json:"critical_context_impact_count"`
	HighContextImpactCount          int   `json:"high_context_impact_count"`
	WorldWritableAIArtifactsCount   int   `json:"world_writable_ai_artifacts_count"`
	SuspiciousAIPromptPatternsCount int   `json:"suspicious_ai_prompt_patterns_count"`
}

type AIToolCatalogItem struct {
	ID             string   `json:"id"`
	DisplayName    string   `json:"display_name"`
	Vendor         string   `json:"vendor"`
	Categories     []string `json:"categories"`
	Detected       bool     `json:"detected"`
	AppPaths       []string `json:"app_paths,omitempty"`
	BinaryPaths    []string `json:"binary_paths,omitempty"`
	ConfigPaths    []string `json:"config_paths,omitempty"`
	CachePaths     []string `json:"cache_paths,omitempty"`
	LogPaths       []string `json:"log_paths,omitempty"`
	ProjectMarkers []string `json:"project_markers,omitempty"`
	Ports          []int    `json:"ports,omitempty"`
	ProcessNames   []string `json:"process_names,omitempty"`
	DiskUsageBytes int64    `json:"disk_usage_bytes"`
	RiskNotes      []string `json:"risk_notes,omitempty"`
	Recommendation string   `json:"recommendation"`
}

type MCPClientCatalogItem struct {
	Name        string   `json:"name"`
	ConfigPaths []string `json:"config_paths"`
	Scope       string   `json:"scope"`
	Detected    bool     `json:"detected"`
	RiskNotes   []string `json:"risk_notes,omitempty"`
}

type MCPServerCatalogItem struct {
	ServerName              string   `json:"server_name"`
	Command                 string   `json:"command,omitempty"`
	Args                    []string `json:"args,omitempty"`
	Transport               string   `json:"transport,omitempty"`
	URL                     string   `json:"url,omitempty"`
	EnvKeysOnly             []string `json:"env_keys_only,omitempty"`
	ConfigPath              string   `json:"config_path"`
	Scope                   string   `json:"scope"`
	RiskCategory            string   `json:"risk_category"`
	CommandExecutionRisk    bool     `json:"command_execution_risk"`
	FilesystemAccessRisk    bool     `json:"filesystem_access_risk"`
	NetworkExfiltrationRisk bool     `json:"network_exfiltration_risk"`
	CredentialAccessRisk    bool     `json:"credential_access_risk"`
	CloudAccessRisk         bool     `json:"cloud_access_risk"`
	BrowserAutomationRisk   bool     `json:"browser_automation_risk"`
	Recommendation          string   `json:"recommendation"`
}

type HermesAgentInfo struct {
	Detected        bool     `json:"detected"`
	ConfigPaths     []string `json:"config_paths"`
	SkillPaths      []string `json:"skill_paths"`
	MemoryPaths     []string `json:"memory_paths"`
	CommandPaths    []string `json:"command_paths"`
	CacheLogPaths   []string `json:"cache_log_paths"`
	EnvKeysDetected []string `json:"env_keys_detected"`
	SizeBytes       int64    `json:"size_bytes"`
	ContextImpact   string   `json:"context_impact"`
	RiskNotes       []string `json:"risk_notes"`
	Recommendations []string `json:"recommendations"`
}

type OpenCodeInfo struct {
	Detected        bool     `json:"detected"`
	AppPaths        []string `json:"app_paths"`
	BinaryPaths     []string `json:"binary_paths"`
	ConfigPaths     []string `json:"config_paths"`
	AgentPaths      []string `json:"agent_paths"`
	PromptRulePaths []string `json:"prompt_rule_paths"`
	CacheLogPaths   []string `json:"cache_log_paths"`
	EnvKeysDetected []string `json:"env_keys_detected"`
	SizeBytes       int64    `json:"size_bytes"`
	ContextImpact   string   `json:"context_impact"`
	RiskNotes       []string `json:"risk_notes"`
	Recommendations []string `json:"recommendations"`
}

type ChineseAIProviderInfo struct {
	ID                  string   `json:"id"`
	DisplayName         string   `json:"display_name"`
	CountryOrRegion     string   `json:"country_or_region"`
	Vendor              string   `json:"vendor"`
	Families            []string `json:"families"`
	Detected            bool     `json:"detected"`
	EnvKeysDetected     []string `json:"env_keys_detected"`
	ConfigPaths         []string `json:"config_paths,omitempty"`
	CachePaths          []string `json:"cache_paths,omitempty"`
	ModelCacheHints     []string `json:"model_cache_hints,omitempty"`
	CLINamesDetected    []string `json:"cli_names_detected,omitempty"`
	ProjectMentions     []string `json:"project_mentions,omitempty"`
	LocalCacheSizeBytes int64    `json:"local_cache_size_bytes"`
	RemoteEndpointHint  bool     `json:"remote_endpoint_hint"`
	RiskLevel           string   `json:"risk_level"`
	RiskNotes           []string `json:"risk_notes,omitempty"`
	Recommendation      string   `json:"recommendation"`
}

type LocalModelInventoryItem struct {
	ToolName        string `json:"tool_name"`
	ProviderHint    string `json:"provider_hint,omitempty"`
	Path            string `json:"path"`
	SizeBytes       int64  `json:"size_bytes"`
	HumanSize       string `json:"human_size"`
	FileCount       int    `json:"file_count"`
	LastModified    string `json:"last_modified"`
	SafeToAutoClean bool   `json:"safe_to_auto_clean"`
	Recommendation  string `json:"recommendation"`
}

type AISecurityToolCatalogItem struct {
	Name           string   `json:"name"`
	Detected       bool     `json:"detected"`
	Paths          []string `json:"paths"`
	PositiveSignal bool     `json:"positive_security_signal"`
	RiskNotes      []string `json:"risk_notes,omitempty"`
}

type AIProviderSummary struct {
	TotalAIToolsDetected          int   `json:"total_ai_tools_detected"`
	TotalMCPClientsDetected       int   `json:"total_mcp_clients_detected"`
	TotalMCPServersDetected       int   `json:"total_mcp_servers_detected"`
	HermesDetected                bool  `json:"hermes_detected"`
	OpenCodeDetected              bool  `json:"opencode_detected"`
	ChineseProvidersDetected      int   `json:"chinese_providers_detected"`
	RemoteProviderEnvKeysDetected int   `json:"remote_provider_env_keys_detected"`
	LocalModelCacheSizeBytes      int64 `json:"local_model_cache_size_bytes"`
	NonLoopbackAIServers          int   `json:"non_loopback_ai_servers"`
}

type Metadata struct {
	ToolName      string    `json:"tool_name"`
	Version       string    `json:"version"`
	GeneratedAt   time.Time `json:"generated_at"`
	OutputDir     string    `json:"output_dir"`
	Deep          bool      `json:"deep"`
	AIAudit       bool      `json:"ai_audit"`
	NoSudo        bool      `json:"no_sudo"`
	CleanDryRun   bool      `json:"clean_dry_run"`
	CleanConfirm  bool      `json:"clean_confirm"`
	ProjectRoot   string    `json:"project_root,omitempty"`
	MaxFileSizeMB int       `json:"max_file_size_mb"`
}

type Report struct {
	Metadata             Metadata                    `json:"metadata"`
	SystemInfo           map[string]string           `json:"system_info"`
	Summary              Summary                     `json:"summary"`
	Findings             []Finding                   `json:"findings"`
	CleanupCandidates    []CleanupCandidate          `json:"cleanup_candidates"`
	AISecurity           AISecuritySummary           `json:"ai_security"`
	AIContextInventory   []AIContextArtifact         `json:"ai_context_inventory"`
	AIRelatedDirectories []AIRelatedDirectory        `json:"ai_related_directories"`
	AISkills             []AIContextArtifact         `json:"ai_skills"`
	AIContextSummary     AIContextSummary            `json:"ai_context_summary"`
	AIToolCatalog        []AIToolCatalogItem         `json:"ai_tool_catalog"`
	MCPClients           []MCPClientCatalogItem      `json:"mcp_clients"`
	MCPServers           []MCPServerCatalogItem      `json:"mcp_servers"`
	HermesAgent          HermesAgentInfo             `json:"hermes_agent"`
	OpenCode             OpenCodeInfo                `json:"opencode"`
	ChineseAIProviders   []ChineseAIProviderInfo     `json:"chinese_ai_providers"`
	LocalModelInventory  []LocalModelInventoryItem   `json:"local_model_inventory"`
	AISecurityTools      []AISecurityToolCatalogItem `json:"ai_security_tools"`
	AIProviderSummary    AIProviderSummary           `json:"ai_provider_summary"`
	GeneratedAt          time.Time                   `json:"generated_at"`
}

type CheckResult struct {
	SystemInfo           map[string]string
	Findings             []Finding
	CleanupCandidates    []CleanupCandidate
	AISecurity           AISecuritySummary
	AIContextInventory   []AIContextArtifact
	AIRelatedDirectories []AIRelatedDirectory
	AISkills             []AIContextArtifact
	AIContextSummary     AIContextSummary
	AIToolCatalog        []AIToolCatalogItem
	MCPClients           []MCPClientCatalogItem
	MCPServers           []MCPServerCatalogItem
	HermesAgent          HermesAgentInfo
	OpenCode             OpenCodeInfo
	ChineseAIProviders   []ChineseAIProviderInfo
	LocalModelInventory  []LocalModelInventoryItem
	AISecurityTools      []AISecurityToolCatalogItem
	AIProviderSummary    AIProviderSummary
}

func (r *CheckResult) Merge(next CheckResult) {
	if r.SystemInfo == nil {
		r.SystemInfo = map[string]string{}
	}
	for k, v := range next.SystemInfo {
		r.SystemInfo[k] = v
	}
	r.Findings = append(r.Findings, next.Findings...)
	r.CleanupCandidates = append(r.CleanupCandidates, next.CleanupCandidates...)
	r.AISecurity.InstalledTools = append(r.AISecurity.InstalledTools, next.AISecurity.InstalledTools...)
	r.AISecurity.MCPConfigs = append(r.AISecurity.MCPConfigs, next.AISecurity.MCPConfigs...)
	r.AISecurity.LocalServers = append(r.AISecurity.LocalServers, next.AISecurity.LocalServers...)
	r.AISecurity.PromptArtifacts = append(r.AISecurity.PromptArtifacts, next.AISecurity.PromptArtifacts...)
	r.AISecurity.Recommendations = append(r.AISecurity.Recommendations, next.AISecurity.Recommendations...)
	r.AIContextInventory = append(r.AIContextInventory, next.AIContextInventory...)
	r.AIRelatedDirectories = append(r.AIRelatedDirectories, next.AIRelatedDirectories...)
	r.AISkills = append(r.AISkills, next.AISkills...)
	r.AIContextSummary.TotalAIDirectories += next.AIContextSummary.TotalAIDirectories
	r.AIContextSummary.TotalAIDirectorySizeBytes += next.AIContextSummary.TotalAIDirectorySizeBytes
	r.AIContextSummary.TotalAIContextArtifacts += next.AIContextSummary.TotalAIContextArtifacts
	r.AIContextSummary.CriticalContextImpactCount += next.AIContextSummary.CriticalContextImpactCount
	r.AIContextSummary.HighContextImpactCount += next.AIContextSummary.HighContextImpactCount
	r.AIContextSummary.WorldWritableAIArtifactsCount += next.AIContextSummary.WorldWritableAIArtifactsCount
	r.AIContextSummary.SuspiciousAIPromptPatternsCount += next.AIContextSummary.SuspiciousAIPromptPatternsCount
	r.AIToolCatalog = append(r.AIToolCatalog, next.AIToolCatalog...)
	r.MCPClients = append(r.MCPClients, next.MCPClients...)
	r.MCPServers = append(r.MCPServers, next.MCPServers...)
	if next.HermesAgent.Detected || len(next.HermesAgent.ConfigPaths) > 0 {
		r.HermesAgent = next.HermesAgent
	}
	if next.OpenCode.Detected || len(next.OpenCode.ConfigPaths) > 0 {
		r.OpenCode = next.OpenCode
	}
	r.ChineseAIProviders = append(r.ChineseAIProviders, next.ChineseAIProviders...)
	r.LocalModelInventory = append(r.LocalModelInventory, next.LocalModelInventory...)
	r.AISecurityTools = append(r.AISecurityTools, next.AISecurityTools...)
	r.AIProviderSummary.TotalAIToolsDetected += next.AIProviderSummary.TotalAIToolsDetected
	r.AIProviderSummary.TotalMCPClientsDetected += next.AIProviderSummary.TotalMCPClientsDetected
	r.AIProviderSummary.TotalMCPServersDetected += next.AIProviderSummary.TotalMCPServersDetected
	r.AIProviderSummary.HermesDetected = r.AIProviderSummary.HermesDetected || next.AIProviderSummary.HermesDetected
	r.AIProviderSummary.OpenCodeDetected = r.AIProviderSummary.OpenCodeDetected || next.AIProviderSummary.OpenCodeDetected
	r.AIProviderSummary.ChineseProvidersDetected += next.AIProviderSummary.ChineseProvidersDetected
	r.AIProviderSummary.RemoteProviderEnvKeysDetected += next.AIProviderSummary.RemoteProviderEnvKeysDetected
	r.AIProviderSummary.LocalModelCacheSizeBytes += next.AIProviderSummary.LocalModelCacheSizeBytes
	r.AIProviderSummary.NonLoopbackAIServers += next.AIProviderSummary.NonLoopbackAIServers
}

type RuntimeConfig struct {
	Version       string
	OutputDir     string
	ProjectRoot   string
	Deep          bool
	AIAudit       bool
	NoSudo        bool
	CleanDryRun   bool
	CleanConfirm  bool
	MaxFileSizeMB int
	HomeDir       string
	StartedAt     time.Time
}
