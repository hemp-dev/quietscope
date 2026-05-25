package safety

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	toml "github.com/pelletier/go-toml/v2"
	"gopkg.in/yaml.v3"
)

type MCPConfigFormat string

const (
	MCPFormatJSON MCPConfigFormat = "json"
	MCPFormatTOML MCPConfigFormat = "toml"
	MCPFormatYAML MCPConfigFormat = "yaml"
)

type MCPServerEntry struct {
	Name       string   `json:"name"`
	Command    string   `json:"command,omitempty"`
	Args       []string `json:"args,omitempty"`
	Transport  string   `json:"transport,omitempty"`
	URL        string   `json:"url,omitempty"`
	EnvKeys    []string `json:"env_keys,omitempty"`
	ConfigPath string   `json:"config_path"`
	Format     string   `json:"format"`
}

func ListMCPServers(path string, home string, projectRoot string, maxBytes int64) ([]MCPServerEntry, error) {
	req := ActionRequest{Action: string(ActionRead), Path: path, Home: home, ProjectRoot: projectRoot, MaxBytes: maxBytes}
	if err := req.normalize(); err != nil {
		return nil, err
	}
	if err := ensureActionAllowed(req, false); err != nil {
		return nil, err
	}
	root, format, err := readStructuredConfig(req.Path, req.MaxBytes)
	if err != nil {
		return nil, err
	}
	var entries []MCPServerEntry
	collectMCPEntries(root, "config", req.Path, string(format), &entries)
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name < entries[j].Name })
	return entries, nil
}

func PreviewMCPAction(req ActionRequest) (ActionResult, error) {
	return previewMCPAction(req, false)
}

func ExecuteMCPAction(req ActionRequest) (ActionResult, error) {
	preview, err := previewMCPAction(req, true)
	if err != nil {
		return ActionResult{}, err
	}
	backupPath, err := CreateBackup(req.Path, req.Home, req.ProjectRoot)
	if err != nil {
		return ActionResult{}, err
	}
	root, format, err := readStructuredConfig(req.Path, req.MaxBytes)
	if err != nil {
		return ActionResult{}, err
	}
	if err := mutateMCPServer(root, req); err != nil {
		return ActionResult{}, err
	}
	next, err := marshalStructuredConfig(root, format)
	if err != nil {
		return ActionResult{}, err
	}
	info, err := os.Lstat(req.Path)
	if err != nil {
		return ActionResult{}, err
	}
	if err := os.WriteFile(req.Path, next, info.Mode().Perm()); err != nil {
		return ActionResult{}, err
	}
	preview.Status = "success"
	preview.BackupPath = backupPath
	preview.Message = "MCP server entry updated structurally. Backup created before write."
	return preview, nil
}

func previewMCPAction(req ActionRequest, executing bool) (ActionResult, error) {
	if req.ServerName == "" {
		return ActionResult{}, fmt.Errorf("server_name is required for MCP server actions")
	}
	if err := req.normalize(); err != nil {
		return ActionResult{}, err
	}
	if err := ensureActionAllowed(req, executing); err != nil {
		return ActionResult{}, err
	}
	root, format, err := readStructuredConfig(req.Path, req.MaxBytes)
	if err != nil {
		return ActionResult{}, err
	}
	if err := mutateMCPServer(root, req); err != nil {
		return ActionResult{}, err
	}
	next, err := marshalStructuredConfig(root, format)
	if err != nil {
		return ActionResult{}, err
	}
	original, err := os.ReadFile(req.Path)
	if err != nil {
		return ActionResult{}, err
	}
	return ActionResult{
		Status:  "preview",
		Action:  req.Action,
		Path:    req.Path,
		Diff:    safeDiff(string(original), string(next)),
		Message: "Preview MCP server change. Backup will be created before writing.",
	}, nil
}

func DetectMCPConfigFormat(path string, data []byte) (MCPConfigFormat, error) {
	ext := strings.ToLower(filepath.Ext(path))
	switch ext {
	case ".json":
		return MCPFormatJSON, nil
	case ".toml":
		return MCPFormatTOML, nil
	case ".yaml", ".yml":
		return MCPFormatYAML, nil
	}
	var raw any
	if json.Unmarshal(data, &raw) == nil {
		return MCPFormatJSON, nil
	}
	if toml.Unmarshal(data, &raw) == nil {
		return MCPFormatTOML, nil
	}
	if yaml.Unmarshal(data, &raw) == nil {
		return MCPFormatYAML, nil
	}
	return "", fmt.Errorf("unsupported config format")
}

func readStructuredConfig(path string, maxBytes int64) (map[string]any, MCPConfigFormat, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, "", err
	}
	if info.IsDir() {
		return nil, "", fmt.Errorf("path %q is a directory", path)
	}
	if maxBytes <= 0 {
		maxBytes = defaultEditableMaxBytes
	}
	if info.Size() > maxBytes {
		return nil, "", fmt.Errorf("path %q exceeds max editable size", path)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, "", err
	}
	format, err := DetectMCPConfigFormat(path, data)
	if err != nil {
		return nil, "", err
	}
	var root any
	switch format {
	case MCPFormatJSON:
		err = json.Unmarshal(data, &root)
	case MCPFormatTOML:
		err = toml.Unmarshal(data, &root)
	case MCPFormatYAML:
		err = yaml.Unmarshal(data, &root)
	default:
		err = fmt.Errorf("unsupported config format")
	}
	if err != nil {
		return nil, "", fmt.Errorf("parser failed, manual review required: %w", err)
	}
	m, ok := normalizeMap(root).(map[string]any)
	if !ok {
		return nil, "", fmt.Errorf("unsupported config root")
	}
	return m, format, nil
}

func marshalStructuredConfig(root map[string]any, format MCPConfigFormat) ([]byte, error) {
	switch format {
	case MCPFormatJSON:
		return json.MarshalIndent(root, "", "  ")
	case MCPFormatTOML:
		return toml.Marshal(root)
	case MCPFormatYAML:
		return yaml.Marshal(root)
	default:
		return nil, fmt.Errorf("unsupported config format")
	}
}

func mutateMCPServer(root map[string]any, req ActionRequest) error {
	parent, name, server, ok := findMCPServer(root, req.ServerName)
	if !ok {
		return fmt.Errorf("MCP server %q not found", req.ServerName)
	}
	switch Action(req.Action) {
	case ActionDisable:
		server["disabled"] = true
		server["enabled"] = false
	case ActionEnable:
		server["disabled"] = false
		server["enabled"] = true
	case ActionDelete:
		delete(parent, name)
	case ActionEdit:
		next := copyStringAnyMap(server)
		for key, value := range req.ServerConfig {
			if value == nil {
				delete(next, key)
				continue
			}
			next[key] = normalizeMap(value)
		}
		parent[name] = next
	default:
		return fmt.Errorf("unsupported MCP action %q", req.Action)
	}
	return nil
}

func findMCPServer(root map[string]any, serverName string) (map[string]any, string, map[string]any, bool) {
	for _, key := range []string{"mcpServers", "servers"} {
		if parent, ok := root[key].(map[string]any); ok {
			for name, raw := range parent {
				if name != serverName {
					continue
				}
				if server, ok := raw.(map[string]any); ok {
					return parent, name, server, true
				}
			}
		}
	}
	return findMCPServerRecursive(root, "config", serverName)
}

func findMCPServerRecursive(value any, name string, serverName string) (map[string]any, string, map[string]any, bool) {
	switch x := value.(type) {
	case map[string]any:
		if name == serverName && looksLikeMCPServerMap(x) {
			return nil, "", nil, false
		}
		for k, v := range x {
			if child, ok := v.(map[string]any); ok && k == serverName && looksLikeMCPServerMap(child) {
				return x, k, child, true
			}
			if parent, foundName, server, ok := findMCPServerRecursive(v, k, serverName); ok {
				return parent, foundName, server, true
			}
		}
	case []any:
		for i, item := range x {
			if parent, foundName, server, ok := findMCPServerRecursive(item, fmt.Sprintf("%s[%d]", name, i), serverName); ok {
				return parent, foundName, server, true
			}
		}
	}
	return nil, "", nil, false
}

func collectMCPEntries(value any, name string, path string, format string, out *[]MCPServerEntry) {
	switch x := value.(type) {
	case map[string]any:
		if servers, ok := x["mcpServers"].(map[string]any); ok {
			for serverName, raw := range servers {
				if server, ok := raw.(map[string]any); ok {
					*out = append(*out, mcpEntryFromMap(serverName, server, path, format))
				}
			}
		}
		if servers, ok := x["servers"].(map[string]any); ok {
			for serverName, raw := range servers {
				if server, ok := raw.(map[string]any); ok {
					*out = append(*out, mcpEntryFromMap(serverName, server, path, format))
				}
			}
		}
		if looksLikeMCPServerMap(x) && name != "config" {
			*out = append(*out, mcpEntryFromMap(name, x, path, format))
			return
		}
		for k, v := range x {
			if k == "mcpServers" || k == "servers" {
				continue
			}
			collectMCPEntries(v, k, path, format, out)
		}
	case []any:
		for i, item := range x {
			collectMCPEntries(item, fmt.Sprintf("%s[%d]", name, i), path, format, out)
		}
	}
}

func mcpEntryFromMap(name string, server map[string]any, path string, format string) MCPServerEntry {
	return MCPServerEntry{
		Name:       name,
		Command:    stringValue(server["command"]),
		Args:       stringSliceValue(server["args"]),
		Transport:  firstStringValue(server, []string{"transport", "type"}),
		URL:        firstStringValue(server, []string{"url", "endpoint", "baseUrl", "serverUrl", "httpUrl"}),
		EnvKeys:    envKeysOnly(server["env"]),
		ConfigPath: path,
		Format:     format,
	}
}

func looksLikeMCPServerMap(server map[string]any) bool {
	return stringValue(server["command"]) != "" ||
		len(stringSliceValue(server["args"])) > 0 ||
		firstStringValue(server, []string{"url", "endpoint", "baseUrl", "serverUrl", "httpUrl"}) != "" ||
		firstStringValue(server, []string{"transport", "type"}) != ""
}

func normalizeMap(value any) any {
	switch x := value.(type) {
	case map[string]any:
		out := make(map[string]any, len(x))
		for k, v := range x {
			out[k] = normalizeMap(v)
		}
		return out
	case map[any]any:
		out := make(map[string]any, len(x))
		for k, v := range x {
			out[fmt.Sprint(k)] = normalizeMap(v)
		}
		return out
	case []any:
		out := make([]any, len(x))
		for i, v := range x {
			out[i] = normalizeMap(v)
		}
		return out
	default:
		return value
	}
}

func copyStringAnyMap(in map[string]any) map[string]any {
	out := make(map[string]any, len(in))
	for k, v := range in {
		out[k] = normalizeMap(v)
	}
	return out
}

func stringValue(value any) string {
	if s, ok := value.(string); ok {
		return s
	}
	return ""
}

func stringSliceValue(value any) []string {
	switch x := value.(type) {
	case []string:
		return append([]string(nil), x...)
	case []any:
		out := make([]string, 0, len(x))
		for _, item := range x {
			if s, ok := item.(string); ok {
				out = append(out, s)
			}
		}
		return out
	default:
		return nil
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
