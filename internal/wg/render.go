package wg

import (
	"embed"
	"fmt"
	"io"
	"net/netip"
	"strings"
	"text/template"
)

//go:embed templates/*.tmpl
var templatesFS embed.FS

var tmpl = template.Must(
	template.New("conf").
		Funcs(template.FuncMap{
			"joinPrefixes": joinStringers[netip.Prefix],
			"joinAddrs":    joinStringers[netip.Addr],
			"joinNames":    joinStringers[DNSName],
		}).
		ParseFS(templatesFS, "templates/*.tmpl"),
)

func Render(w io.Writer, c Config) error {
	return tmpl.ExecuteTemplate(w, "config.tmpl", c)
}

func joinStringers[S fmt.Stringer](xs []S, sep string) string {
	var sb strings.Builder
	for i, s := range xs {
		if i > 0 {
			sb.WriteString(sep)
		}
		sb.WriteString(s.String())
	}
	return sb.String()
}
