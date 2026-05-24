package platform

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"io"
	"os"
	"strings"
)

func ParsePlistFile(path string, maxBytes int64) (map[string]any, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if maxBytes > 0 && info.Size() > maxBytes {
		return nil, fmt.Errorf("plist too large")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	trimmed := bytes.TrimSpace(data)
	if !bytes.HasPrefix(trimmed, []byte("<")) {
		return nil, fmt.Errorf("binary plist parsing is not supported without external dependencies")
	}
	decoder := xml.NewDecoder(bytes.NewReader(data))
	for {
		tok, tokenErr := decoder.Token()
		if tokenErr != nil {
			if tokenErr == io.EOF {
				break
			}
			return nil, tokenErr
		}
		if start, ok := tok.(xml.StartElement); ok && start.Name.Local == "dict" {
			value, parseErr := parsePlistDict(decoder)
			if parseErr != nil {
				return nil, parseErr
			}
			return value, nil
		}
	}
	return nil, fmt.Errorf("no plist dict found")
}

func parsePlistDict(decoder *xml.Decoder) (map[string]any, error) {
	result := map[string]any{}
	var key string
	for {
		tok, err := decoder.Token()
		if err != nil {
			return result, err
		}
		switch t := tok.(type) {
		case xml.StartElement:
			if t.Name.Local == "key" {
				text, textErr := readElementText(decoder, t.Name.Local)
				if textErr != nil {
					return result, textErr
				}
				key = strings.TrimSpace(text)
				continue
			}
			if key == "" {
				if err := skipElement(decoder, t.Name.Local); err != nil {
					return result, err
				}
				continue
			}
			value, valueErr := parsePlistValue(decoder, t)
			if valueErr != nil {
				return result, valueErr
			}
			result[key] = value
			key = ""
		case xml.EndElement:
			if t.Name.Local == "dict" {
				return result, nil
			}
		}
	}
}

func parsePlistValue(decoder *xml.Decoder, start xml.StartElement) (any, error) {
	switch start.Name.Local {
	case "string", "data", "date", "integer", "real":
		return strings.TrimSpace(readTextMust(decoder, start.Name.Local)), nil
	case "true":
		return true, nil
	case "false":
		return false, nil
	case "array":
		return parsePlistArray(decoder)
	case "dict":
		return parsePlistDict(decoder)
	default:
		return "", skipElement(decoder, start.Name.Local)
	}
}

func parsePlistArray(decoder *xml.Decoder) ([]any, error) {
	var values []any
	for {
		tok, err := decoder.Token()
		if err != nil {
			return values, err
		}
		switch t := tok.(type) {
		case xml.StartElement:
			value, valueErr := parsePlistValue(decoder, t)
			if valueErr != nil {
				return values, valueErr
			}
			values = append(values, value)
		case xml.EndElement:
			if t.Name.Local == "array" {
				return values, nil
			}
		}
	}
}

func readTextMust(decoder *xml.Decoder, end string) string {
	text, _ := readElementText(decoder, end)
	return text
}

func readElementText(decoder *xml.Decoder, end string) (string, error) {
	var b strings.Builder
	for {
		tok, err := decoder.Token()
		if err != nil {
			return b.String(), err
		}
		switch t := tok.(type) {
		case xml.CharData:
			b.Write([]byte(t))
		case xml.EndElement:
			if t.Name.Local == end {
				return b.String(), nil
			}
		}
	}
}

func skipElement(decoder *xml.Decoder, end string) error {
	depth := 1
	for depth > 0 {
		tok, err := decoder.Token()
		if err != nil {
			return err
		}
		switch t := tok.(type) {
		case xml.StartElement:
			if t.Name.Local == end {
				depth++
			}
		case xml.EndElement:
			if t.Name.Local == end {
				depth--
			}
		}
	}
	return nil
}
