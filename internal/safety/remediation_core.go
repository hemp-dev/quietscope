package safety

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

type Action string

const (
	ActionRead    Action = "read"
	ActionEdit    Action = "edit"
	ActionDisable Action = "disable"
	ActionEnable  Action = "enable"
	ActionDelete  Action = "delete"
	ActionFix     Action = "fix"
	ActionRestore Action = "restore"
	ActionClean   Action = "clean"
)

type ActionRequest struct {
	Action       string         `json:"action"`
	Path         string         `json:"path"`
	ArtifactID   string         `json:"artifact_id,omitempty"`
	ServerName   string         `json:"server_name,omitempty"`
	Content      string         `json:"content,omitempty"`
	ServerConfig map[string]any `json:"server_config,omitempty"`
	BackupPath   string         `json:"backup_path,omitempty"`
	Home         string         `json:"-"`
	ProjectRoot  string         `json:"-"`
	MaxBytes     int64          `json:"max_bytes,omitempty"`
}

type ActionResult struct {
	Status     string `json:"status"`
	Action     string `json:"action"`
	Path       string `json:"path"`
	BackupPath string `json:"backup_path,omitempty"`
	Diff       string `json:"diff,omitempty"`
	Message    string `json:"message,omitempty"`
	Content    string `json:"content,omitempty"`
	ReadOnly   bool   `json:"read_only,omitempty"`
}

type backupManifest struct {
	OriginalPath string    `json:"original_path"`
	BackupPath   string    `json:"backup_path"`
	CreatedAt    time.Time `json:"created_at"`
	IsDir        bool      `json:"is_dir"`
}

const defaultEditableMaxBytes int64 = 2 * 1024 * 1024

func PreviewAction(req ActionRequest) (ActionResult, error) {
	if err := req.normalize(); err != nil {
		return ActionResult{}, err
	}
	if req.Action == string(ActionRestore) {
		return previewRestore(req)
	}
	if err := ensureActionAllowed(req, false); err != nil {
		return ActionResult{}, err
	}
	if req.ServerName != "" {
		return PreviewMCPAction(req)
	}
	switch Action(req.Action) {
	case ActionRead:
		content, err := ReadArtifact(req.Path, req.Home, req.ProjectRoot, req.MaxBytes)
		if err != nil {
			return ActionResult{}, err
		}
		return ActionResult{Status: "preview", Action: req.Action, Path: req.Path, Content: content, ReadOnly: true, Message: "Safe artifact read. Secret paths are blocked."}, nil
	case ActionEdit:
		return previewEdit(req)
	case ActionDisable:
		return previewRename(req, req.Path+".disabled", "disable")
	case ActionEnable:
		if !strings.HasSuffix(req.Path, ".disabled") {
			return ActionResult{}, fmt.Errorf("path %q is not a disabled artifact", req.Path)
		}
		return previewRename(req, strings.TrimSuffix(req.Path, ".disabled"), "enable")
	case ActionDelete, ActionClean:
		return previewDelete(req)
	case ActionFix:
		return previewFix(req)
	default:
		return ActionResult{}, fmt.Errorf("unknown action: %s", req.Action)
	}
}

func ExecuteAction(req ActionRequest) (ActionResult, error) {
	if err := req.normalize(); err != nil {
		return ActionResult{}, err
	}
	if req.Action == string(ActionRestore) {
		return RestoreBackup(req)
	}
	if req.ServerName != "" {
		return ExecuteMCPAction(req)
	}
	preview, err := PreviewAction(req)
	if err != nil {
		return ActionResult{}, err
	}
	if err := ensureActionAllowed(req, true); err != nil {
		return ActionResult{}, err
	}
	switch Action(req.Action) {
	case ActionRead:
		preview.Status = "success"
		return preview, nil
	case ActionEdit:
		_, mode, err := readExistingFile(req.Path, req.Home, req.ProjectRoot, req.MaxBytes)
		if err != nil {
			return ActionResult{}, err
		}
		backupPath, err := CreateBackup(req.Path, req.Home, req.ProjectRoot)
		if err != nil {
			return ActionResult{}, err
		}
		if err := os.WriteFile(req.Path, []byte(req.Content), mode); err != nil {
			return ActionResult{}, err
		}
		preview.Status = "success"
		preview.BackupPath = backupPath
		preview.Message = "Artifact saved. Backup created before write."
		return preview, nil
	case ActionDisable:
		backupPath, err := CreateBackup(req.Path, req.Home, req.ProjectRoot)
		if err != nil {
			return ActionResult{}, err
		}
		if err := os.Rename(req.Path, req.Path+".disabled"); err != nil {
			return ActionResult{}, err
		}
		preview.Status = "success"
		preview.BackupPath = backupPath
		return preview, nil
	case ActionEnable:
		backupPath, err := CreateBackup(req.Path, req.Home, req.ProjectRoot)
		if err != nil {
			return ActionResult{}, err
		}
		if err := os.Rename(req.Path, strings.TrimSuffix(req.Path, ".disabled")); err != nil {
			return ActionResult{}, err
		}
		preview.Status = "success"
		preview.BackupPath = backupPath
		return preview, nil
	case ActionDelete, ActionClean:
		backupPath, err := CreateBackup(req.Path, req.Home, req.ProjectRoot)
		if err != nil {
			return ActionResult{}, err
		}
		if err := os.RemoveAll(req.Path); err != nil {
			return ActionResult{}, err
		}
		preview.Status = "success"
		preview.BackupPath = backupPath
		return preview, nil
	case ActionFix:
		original, mode, err := readExistingFile(req.Path, req.Home, req.ProjectRoot, req.MaxBytes)
		if err != nil {
			return ActionResult{}, err
		}
		next, modified, err := fixedAISkillContent(req.Path, original)
		if err != nil {
			return ActionResult{}, err
		}
		if !modified {
			preview.Status = "success"
			preview.Message = "No suspicious patterns matched; no write performed."
			return preview, nil
		}
		backupPath, err := CreateBackup(req.Path, req.Home, req.ProjectRoot)
		if err != nil {
			return ActionResult{}, err
		}
		if err := os.WriteFile(req.Path, next, mode); err != nil {
			return ActionResult{}, err
		}
		preview.Status = "success"
		preview.BackupPath = backupPath
		return preview, nil
	default:
		return ActionResult{}, fmt.Errorf("unknown action: %s", req.Action)
	}
}

func ReadArtifact(path string, home string, projectRoot string, maxBytes int64) (string, error) {
	req := ActionRequest{Action: string(ActionRead), Path: path, Home: home, ProjectRoot: projectRoot, MaxBytes: maxBytes}
	if err := req.normalize(); err != nil {
		return "", err
	}
	if err := ensureActionAllowed(req, false); err != nil {
		return "", err
	}
	data, _, err := readExistingFile(req.Path, req.Home, req.ProjectRoot, req.MaxBytes)
	if err != nil {
		return "", err
	}
	return RedactSensitiveText(string(data)), nil
}

func SaveArtifact(path string, content string, home string, projectRoot string) (ActionResult, error) {
	return ExecuteAction(ActionRequest{Action: string(ActionEdit), Path: path, Content: content, Home: home, ProjectRoot: projectRoot})
}

func CreateBackup(path string, home string, projectRoot string) (string, error) {
	if !IsPathSafeToRemediate(path, home, projectRoot) {
		return "", fmt.Errorf("path %q is not safe/allowlisted for backup", path)
	}
	if err := rejectSymlinkPath(path, true); err != nil {
		return "", err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return "", err
	}
	if err := rejectNestedSymlinks(path); err != nil {
		return "", err
	}
	root := backupRoot(home)
	if err := os.MkdirAll(root, 0o700); err != nil {
		return "", err
	}
	backupPath := filepath.Join(root, backupName(path, info.IsDir()))
	if info.IsDir() {
		if err := copyDir(path, backupPath); err != nil {
			return "", err
		}
	} else {
		if err := copyFile(path, backupPath, info.Mode().Perm()); err != nil {
			return "", err
		}
	}
	manifest := backupManifest{
		OriginalPath: path,
		BackupPath:   backupPath,
		CreatedAt:    time.Now(),
		IsDir:        info.IsDir(),
	}
	data, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return "", err
	}
	if err := os.WriteFile(backupPath+".manifest.json", data, 0o600); err != nil {
		return "", err
	}
	return backupPath, nil
}

func RestoreBackup(req ActionRequest) (ActionResult, error) {
	if err := req.normalize(); err != nil {
		return ActionResult{}, err
	}
	if req.BackupPath == "" {
		return ActionResult{}, errors.New("backup_path is required")
	}
	if err := ensureBackupPath(req.BackupPath, req.Home); err != nil {
		return ActionResult{}, err
	}
	if !IsPathSafeToRemediate(req.Path, req.Home, req.ProjectRoot) {
		return ActionResult{}, fmt.Errorf("path %q is not safe/allowlisted for restore", req.Path)
	}
	if err := rejectSymlinkPath(req.BackupPath, true); err != nil {
		return ActionResult{}, err
	}
	if err := rejectSymlinkPath(req.Path, false); err != nil {
		return ActionResult{}, err
	}
	backupInfo, err := os.Lstat(req.BackupPath)
	if err != nil {
		return ActionResult{}, err
	}
	var currentBackup string
	if _, statErr := os.Lstat(req.Path); statErr == nil {
		currentBackup, err = CreateBackup(req.Path, req.Home, req.ProjectRoot)
		if err != nil {
			return ActionResult{}, err
		}
		if err := os.RemoveAll(req.Path); err != nil {
			return ActionResult{}, err
		}
	}
	if backupInfo.IsDir() {
		if err := copyDir(req.BackupPath, req.Path); err != nil {
			return ActionResult{}, err
		}
	} else {
		if err := os.MkdirAll(filepath.Dir(req.Path), 0o700); err != nil {
			return ActionResult{}, err
		}
		if err := copyFile(req.BackupPath, req.Path, backupInfo.Mode().Perm()); err != nil {
			return ActionResult{}, err
		}
	}
	msg := "Restored previous version."
	if currentBackup != "" {
		msg += " Current version was backed up first."
	}
	return ActionResult{Status: "success", Action: string(ActionRestore), Path: req.Path, BackupPath: currentBackup, Message: msg}, nil
}

func previewRestore(req ActionRequest) (ActionResult, error) {
	if req.BackupPath == "" {
		return ActionResult{}, errors.New("backup_path is required")
	}
	if err := ensureBackupPath(req.BackupPath, req.Home); err != nil {
		return ActionResult{}, err
	}
	if !IsPathSafeToRemediate(req.Path, req.Home, req.ProjectRoot) {
		return ActionResult{}, fmt.Errorf("path %q is not safe/allowlisted for restore", req.Path)
	}
	oldData, _ := os.ReadFile(req.Path)
	newData, _ := os.ReadFile(req.BackupPath)
	return ActionResult{
		Status:  "preview",
		Action:  req.Action,
		Path:    req.Path,
		Diff:    safeDiff(string(oldData), string(newData)),
		Message: "Restore previous version. Backup will be created for the current target if it exists.",
	}, nil
}

func previewEdit(req ActionRequest) (ActionResult, error) {
	oldData, _, err := readExistingFile(req.Path, req.Home, req.ProjectRoot, req.MaxBytes)
	if err != nil {
		return ActionResult{}, err
	}
	return ActionResult{
		Status:  "preview",
		Action:  req.Action,
		Path:    req.Path,
		Diff:    safeDiff(string(oldData), req.Content),
		Message: "Preview changes. Backup will be created before writing.",
	}, nil
}

func previewRename(req ActionRequest, nextPath string, label string) (ActionResult, error) {
	if err := rejectSymlinkPath(nextPath, false); err != nil {
		return ActionResult{}, err
	}
	return ActionResult{
		Status:  "preview",
		Action:  req.Action,
		Path:    req.Path,
		Diff:    fmt.Sprintf("rename %s -> %s", req.Path, nextPath),
		Message: "Preview " + label + ". Backup will be created before rename.",
	}, nil
}

func previewDelete(req ActionRequest) (ActionResult, error) {
	info, err := os.Lstat(req.Path)
	if err != nil {
		return ActionResult{}, err
	}
	msg := "Preview delete. Backup will be created before removal."
	if Action(req.Action) == ActionClean {
		msg = "Preview cache cleanup. Backup will be created before removal."
	}
	if info.IsDir() {
		return ActionResult{Status: "preview", Action: req.Action, Path: req.Path, Diff: "remove directory: " + req.Path, Message: msg}, nil
	}
	data, _ := os.ReadFile(req.Path)
	return ActionResult{Status: "preview", Action: req.Action, Path: req.Path, Diff: safeDiff(string(data), ""), Message: msg}, nil
}

func previewFix(req ActionRequest) (ActionResult, error) {
	oldData, _, err := readExistingFile(req.Path, req.Home, req.ProjectRoot, req.MaxBytes)
	if err != nil {
		return ActionResult{}, err
	}
	next, modified, err := fixedAISkillContent(req.Path, oldData)
	if err != nil {
		return ActionResult{}, err
	}
	msg := "No suspicious patterns matched; no write required."
	if modified {
		msg = "Preview pattern fix. Backup will be created before writing."
	}
	return ActionResult{Status: "preview", Action: req.Action, Path: req.Path, Diff: safeDiff(string(oldData), string(next)), Message: msg}, nil
}

func ensureActionAllowed(req ActionRequest, write bool) error {
	if req.Path == "" {
		return errors.New("path is required")
	}
	if IsSecretPath(req.Path, req.Home) {
		return fmt.Errorf("path %q is secret-sensitive and cannot be read or modified", req.Path)
	}
	if err := rejectSymlinkPath(req.Path, true); err != nil {
		return err
	}
	if write {
		if !IsPathSafeToRemediate(req.Path, req.Home, req.ProjectRoot) {
			return fmt.Errorf("path %q is not safe/allowlisted for modification", req.Path)
		}
	} else if !IsManageablePathAllowed(req.Path, req.Home, req.ProjectRoot) && !IsCleanupAllowed(req.Path, req.Home) {
		return fmt.Errorf("path %q is not safe/allowlisted for management", req.Path)
	}
	if Action(req.Action) == ActionClean && !IsCleanupAllowed(req.Path, req.Home) {
		return fmt.Errorf("path %q is not an allowlisted cleanup candidate", req.Path)
	}
	return nil
}

func (r *ActionRequest) normalize() error {
	r.Action = strings.TrimSpace(strings.ToLower(r.Action))
	r.Path = strings.TrimSpace(r.Path)
	if r.Path != "" {
		r.Path = filepath.Clean(r.Path)
	}
	r.BackupPath = strings.TrimSpace(r.BackupPath)
	if r.BackupPath != "" {
		r.BackupPath = filepath.Clean(r.BackupPath)
	}
	r.Home = strings.TrimSpace(r.Home)
	if r.Home != "" {
		r.Home = filepath.Clean(r.Home)
	}
	r.ProjectRoot = strings.TrimSpace(r.ProjectRoot)
	if r.ProjectRoot != "" {
		r.ProjectRoot = filepath.Clean(r.ProjectRoot)
	}
	if r.MaxBytes <= 0 {
		r.MaxBytes = defaultEditableMaxBytes
	}
	if r.Home == "." || r.Home == "" {
		return errors.New("home directory is required")
	}
	return nil
}

func readExistingFile(path string, home string, projectRoot string, maxBytes int64) ([]byte, os.FileMode, error) {
	if IsSecretPath(path, home) {
		return nil, 0, fmt.Errorf("path %q is secret-sensitive and cannot be read", path)
	}
	if !IsManageablePathAllowed(path, home, projectRoot) {
		return nil, 0, fmt.Errorf("path %q is not safe/allowlisted for reading", path)
	}
	if err := rejectSymlinkPath(path, true); err != nil {
		return nil, 0, err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return nil, 0, err
	}
	if info.IsDir() {
		return nil, 0, fmt.Errorf("path %q is a directory", path)
	}
	if info.Size() > maxBytes {
		return nil, 0, fmt.Errorf("path %q exceeds max editable size", path)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, 0, err
	}
	return data, info.Mode().Perm(), nil
}

func rejectSymlinkPath(path string, mustExist bool) error {
	clean := filepath.Clean(path)
	if clean == "." || clean == "" {
		return errors.New("empty path")
	}
	if !filepath.IsAbs(clean) {
		abs, err := filepath.Abs(clean)
		if err != nil {
			return err
		}
		clean = abs
	}
	volume := filepath.VolumeName(clean)
	rest := strings.TrimPrefix(clean, volume)
	sep := string(os.PathSeparator)
	current := volume
	if strings.HasPrefix(rest, sep) {
		current += sep
		rest = strings.TrimPrefix(rest, sep)
	}
	parts := strings.Split(rest, sep)
	for i, part := range parts {
		if part == "" {
			continue
		}
		current = filepath.Join(current, part)
		info, err := os.Lstat(current)
		if err != nil {
			if os.IsNotExist(err) && (!mustExist || i == len(parts)-1) {
				return nil
			}
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			if isSystemCompatibilitySymlink(current) {
				continue
			}
			return fmt.Errorf("path %q includes symlink component %q; remediation is blocked", path, current)
		}
	}
	return nil
}

func isSystemCompatibilitySymlink(path string) bool {
	switch filepath.Clean(path) {
	case "/var", "/tmp", "/etc":
		return true
	default:
		return false
	}
}

func rejectNestedSymlinks(root string) error {
	return filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		info, infoErr := d.Info()
		if infoErr != nil {
			return infoErr
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("path %q contains symlink %q; backup/remediation is blocked", root, path)
		}
		return nil
	})
}

func backupRoot(home string) string {
	if home == "" || home == "." {
		home = os.TempDir()
	}
	return filepath.Join(home, ".quietscope", "backups")
}

func backupName(path string, isDir bool) string {
	sum := sha256.Sum256([]byte(path))
	ext := filepath.Ext(path)
	if isDir || ext == "" {
		ext = ".bak"
	}
	base := filepath.Base(path)
	base = strings.NewReplacer("/", "-", " ", "-", ":", "-").Replace(base)
	if len(base) > 40 {
		base = base[:40]
	}
	return time.Now().UTC().Format("20060102T150405.000000000Z") + "-" + base + "-" + hex.EncodeToString(sum[:])[:12] + ext
}

func ensureBackupPath(path string, home string) error {
	root := backupRoot(home)
	rel, err := filepath.Rel(root, filepath.Clean(path))
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
		return fmt.Errorf("backup path %q is outside quietscope backup root", path)
	}
	return nil
}

func copyFile(src string, dst string, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
		return err
	}
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_EXCL|os.O_WRONLY, mode)
	if err != nil {
		return err
	}
	_, copyErr := io.Copy(out, in)
	closeErr := out.Close()
	if copyErr != nil {
		return copyErr
	}
	return closeErr
}

func copyDir(src string, dst string) error {
	return filepath.WalkDir(src, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		info, infoErr := d.Info()
		if infoErr != nil {
			return infoErr
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("refusing to copy symlink %q", path)
		}
		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		target := filepath.Join(dst, rel)
		if d.IsDir() {
			return os.MkdirAll(target, info.Mode().Perm())
		}
		return copyFile(path, target, info.Mode().Perm())
	})
}

func safeDiff(before string, after string) string {
	before = RedactSensitiveText(before)
	after = RedactSensitiveText(after)
	if before == after {
		return "no changes"
	}
	beforeLines := strings.Split(before, "\n")
	afterLines := strings.Split(after, "\n")
	maxLines := 200
	var out []string
	out = append(out, "--- before", "+++ after")
	i, j := 0, 0
	for (i < len(beforeLines) || j < len(afterLines)) && len(out) < maxLines {
		if i < len(beforeLines) && j < len(afterLines) && beforeLines[i] == afterLines[j] {
			out = append(out, " "+beforeLines[i])
			i++
			j++
			continue
		}
		if i < len(beforeLines) {
			out = append(out, "-"+beforeLines[i])
			i++
		}
		if j < len(afterLines) {
			out = append(out, "+"+afterLines[j])
			j++
		}
	}
	if i < len(beforeLines) || j < len(afterLines) {
		out = append(out, "... diff truncated ...")
	}
	return strings.Join(out, "\n")
}

func BackupAvailableForPath(path string, home string) bool {
	root := backupRoot(home)
	entries, err := os.ReadDir(root)
	if err != nil {
		return false
	}
	var manifests []string
	for _, entry := range entries {
		if strings.HasSuffix(entry.Name(), ".manifest.json") {
			manifests = append(manifests, filepath.Join(root, entry.Name()))
		}
	}
	sort.Strings(manifests)
	for _, manifestPath := range manifests {
		data, err := os.ReadFile(manifestPath)
		if err != nil {
			continue
		}
		var manifest backupManifest
		if json.Unmarshal(data, &manifest) == nil && manifest.OriginalPath == path {
			return true
		}
	}
	return false
}
