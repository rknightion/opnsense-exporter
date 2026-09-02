// Command metriclint enforces the repository's Prometheus metric naming
// contract. It is also exercised by a repository-scan test in
// internal/metriclint, so the CI test job cannot bypass the check by omitting a
// local recipe.
package main

import (
	"fmt"
	"os"

	"github.com/rknightion/opnsense2otel/v4/internal/metriclint"
)

func main() {
	root, err := metriclint.FindRepositoryRoot(".")
	if err != nil {
		fmt.Fprintln(os.Stderr, "metriclint:", err)
		os.Exit(2)
	}
	if err := metriclint.CheckRepository(root); err != nil {
		fmt.Fprintln(os.Stderr, "metriclint:", err)
		os.Exit(1)
	}
	fmt.Println("metric naming lint: OK")
}
