package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "Start the glyph server",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("Starting glyph server...")
		// Will connect to config loader, auth, proxy, etc.
	},
}

func init() {
	rootCmd.AddCommand(serveCmd)
}
