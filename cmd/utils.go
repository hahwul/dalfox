package cmd

import (
	"strings"
	"text/template"
	"unicode"
	"unicode/utf8"

	"github.com/spf13/cobra"
)

// This file contains utility functions for managing command-line help output
// and other shared functionality used across the different commands

// SubCommandCustomHelpFunc provides a custom help formatter for subcommands
// This function is shared across all subcommands to ensure consistent help display
// It leverages templates to create a more organized and user-friendly help output
func SubCommandCustomHelpFunc(c *cobra.Command, _ []string) {
	// Prepare data structure to pass to the help template
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

	// Set the description text, using the long description if available, otherwise use short
	// Using the safe version to avoid potential infinite recursion
	if c.Long != "" {
		templateData.LongOrUsage = c.Long
	} else {
		templateData.LongOrUsage = c.Short
	}

	tmpl := template.New("customHelp")

	// Add utility functions to the template for text formatting
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
// It sets up consistent help formatting across all DalFox commands
func ApplySubCommandCustomHelp(cmd *cobra.Command) {
	// Apply the custom help template to the command
	cmd.SetHelpTemplate(customHelpTemplate)

	// Set the custom help function that will render the template
	cmd.SetHelpFunc(SubCommandCustomHelpFunc)

	// Override the usage function to directly print help without using UsageString()
	// This prevents potential infinite recursion that can occur in Cobra's default implementation
	cmd.SetUsageFunc(func(c *cobra.Command) error {
		// Directly call our help function
		SubCommandCustomHelpFunc(c, nil)
		return nil
	})
}
