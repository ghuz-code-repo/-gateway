package models

import (
	"golang.org/x/text/cases"
	"golang.org/x/text/language"
)

// titleCase converts a string to title case using the proper unicode-aware method.
// Replaces deprecated strings.Title.
func titleCase(s string) string {
	return cases.Title(language.Und).String(s)
}
