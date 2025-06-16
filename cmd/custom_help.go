package cmd

// customHelpTemplate defines the format for help output in DalFox commands
// This template provides a structured and consistent display of command information
// including usage, available commands, flags, examples, and more
const customHelpTemplate = `{{.LongOrUsage}}

Usage:
  {{.Command.UseLine}}{{if .Command.HasAvailableSubCommands}} [command]{{end}}
{{- if .Command.HasAvailableSubCommands}}

Available Commands:{{range .Command.Commands}}{{if (or .IsAvailableCommand .IsAdditionalHelpTopicCommand)}}
  {{rpad .Name .NamePadding }} {{.Short}}{{end}}{{end}}{{end}}
{{- if .ShowFlagGroups }}

{{range .FlagGroupsRef}}{{.Title}}:
{{.Flags.FlagUsages | trimTrailingWhitespaces}}

{{end}}{{end}}
{{- if .Command.HasAvailableLocalFlags}}
  {{- if .Command.HasParent}}
Local Flags:
{{.Command.LocalFlags.FlagUsages | trimTrailingWhitespaces}}
  {{- else if .ShowFlagGroups}}
    {{- $helpFlag := .Command.LocalFlags.Lookup "help" }}
    {{- if $helpFlag }}
Local Flags:
  -h, --help   {{$helpFlag.Usage}}{{end}}
  {{- else}}
Local Flags:
{{.Command.LocalFlags.FlagUsages | trimTrailingWhitespaces}}
  {{- end}}
{{- end}}
{{- if .Command.HasAvailableInheritedFlags}}{{if not .ShowFlagGroups }}
Global Flags:
{{.Command.InheritedFlags.FlagUsages | trimTrailingWhitespaces}}{{end}}{{end}}
{{- if .Command.HasExample}}
Examples:
{{.Command.Example}}{{end}}
{{- if .Command.HasHelpSubCommands}}
Additional help topics:{{range .Command.Commands}}{{if .IsAdditionalHelpTopicCommand}}
  {{rpad .Command.CommandPath .Command.CommandPathPadding}} {{.Short}}{{end}}{{end}}{{end}}
{{- if .Command.HasAvailableSubCommands}}

Use "{{.Command.CommandPath}} [command] --help" for more information about a command.{{end}}`
