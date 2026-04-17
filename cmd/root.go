package cmd

import (
	"context"
	"os"

	"github.com/appscodelabs/govulnfix/internal/remediate"
	"github.com/spf13/cobra"
)

func Execute() error {
	return newRootCmd().Execute()
}

func newRootCmd() *cobra.Command {
	var cfg remediate.Config

	cmd := &cobra.Command{
		Use:   "govulnfix",
		Short: "Update go.mod until govulncheck and Dependabot Go vulnerabilities are cleared",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg.Stdout = cmd.OutOrStdout()
			cfg.Stderr = cmd.ErrOrStderr()
			return remediate.Run(cmd.Context(), cfg)
		},
		SilenceUsage: true,
	}

	cmd.SetOut(os.Stdout)
	cmd.SetErr(os.Stderr)
	cmd.SetContext(context.Background())

	flags := cmd.Flags()
	flags.StringVar(&cfg.ProjectDir, "dir", ".", "Path to the Go module to update")
	flags.StringVar(&cfg.Repo, "repo", "", "GitHub repository in owner/repo form; defaults to GITHUB_REPOSITORY or origin remote")
	flags.StringVar(&cfg.GitHubToken, "github-token", "", "GitHub token with security_events or Dependabot alerts read access; defaults to GITHUB_TOKEN")
	flags.StringSliceVar(&cfg.Patterns, "pattern", []string{"./..."}, "Package patterns passed to govulncheck")
	flags.IntVar(&cfg.MaxIterations, "max-iterations", 10, "Maximum remediation passes to attempt")
	flags.BoolVar(&cfg.DryRun, "dry-run", false, "Print the planned module upgrades without changing go.mod")

	return cmd
}
