package report

import (
	"encoding/json"
	"os"

	"github.com/projectauthors/quietscope/internal/audit"
)

func WriteJSON(path string, report audit.Report) error {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	defer file.Close()
	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	encoder.SetEscapeHTML(true)
	return encoder.Encode(report)
}
