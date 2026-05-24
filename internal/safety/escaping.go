package safety

import "html"

func EscapeHTML(input string) string {
	return html.EscapeString(input)
}
