package cmd

import (
	"strings"
	"text/template"
	"unicode"
	"unicode/utf8"

	"github.com/spf13/cobra"
)

// safeUsageString returns a command's usage string but avoids recursion
func safeUsageString(c *cobra.Command) string {
	// Return just the command's Long/Short directly instead of calling UsageString()
	// to avoid potential infinite recursion
	if c.Long != "" {
		return c.Long
	}
	return c.Short
}

// SubCommandCustomHelpFunc provides a help function that only shows help once
// This function is shared across all subcommands to ensure consistent help display
func SubCommandCustomHelpFunc(c *cobra.Command, _ []string) {
	// Data to pass to the template
	templateData := struct {
		Command        *cobra.Command
		FlagGroupsRef  []FlagGroup
		ShowFlagGroups bool
		LongOrUsage    string
	}{
		Command:        c,
		FlagGroupsRef:  flagGroups,
		ShowFlagGroups: len(flagGroups) > 0,
	}

	// Logic for LongOrUsage - Use safe version to avoid recursion
	if c.Long != "" {
		templateData.LongOrUsage = c.Long
	} else {
		templateData.LongOrUsage = c.Short
	}

	tmpl := template.New("customHelp")

	// Add functions to template
	tmpl.Funcs(template.FuncMap{
		"rpad": func(s string, padding int) string {
			sLen := utf8.RuneCountInString(s)
			if padding <= sLen {
				return s
			}
			return s + strings.Repeat(" ", padding-sLen)
		},
		"trimTrailingWhitespaces": func(s string) string {
			return strings.TrimRightFunc(s, unicode.IsSpace)
		},
	})

	parsedTmpl, err := tmpl.Parse(customHelpTemplate)
	if err != nil {
		c.PrintErrln("Error parsing custom help template:", err)
		return
	}

	err = parsedTmpl.Execute(c.OutOrStdout(), templateData)
	if err != nil {
		c.PrintErrln("Error executing custom help template:", err)
	}
}

// ApplySubCommandCustomHelp configures a subcommand to use the custom help format
// This function should be called in the init() function of each subcommand
func ApplySubCommandCustomHelp(cmd *cobra.Command) {
	// Set help template
	cmd.SetHelpTemplate(customHelpTemplate)

	// Set custom help function
	cmd.SetHelpFunc(SubCommandCustomHelpFunc)

	// Override usage function to directly print help without using UsageString()
	// This prevents potential infinite recursion
	cmd.SetUsageFunc(func(c *cobra.Command) error {
		// Directly call our help function
		SubCommandCustomHelpFunc(c, nil)
		return nil
	})
}
