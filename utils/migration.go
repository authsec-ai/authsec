package utils

import (
	"fmt"
	"io/ioutil"
	"log"
	"path/filepath"
	"sort"
	"strings"

	"github.com/authsec-ai/authsec/config"
)

// RunMigrations executes all SQL migration files in order
func RunMigrations(migrationsDir string) error {

	log.Printf("Starting Migrations ...")
	// Get all migration files
	files, err := filepath.Glob(filepath.Join(migrationsDir, "*.sql"))
	if err != nil {
		return fmt.Errorf("failed to read migration files: %v", err)
	}

	// Sort files by name (assuming they start with numbers like 001_, 002_, etc.)
	sort.Strings(files)

	// Execute each migration file
	for _, file := range files {
		log.Printf("Running migration: %s", filepath.Base(file))

		content, err := ioutil.ReadFile(file)
		if err != nil {
			return fmt.Errorf("failed to read migration file %s: %v", file, err)
		}

		// Split content by semicolon to handle multiple statements
		statements := strings.Split(string(content), ";")

		for _, stmt := range statements {
			stmt = strings.TrimSpace(stmt)
			if stmt == "" {
				continue
			}

			db := config.GetDatabase()
			if _, err := db.Exec(stmt); err != nil {
				return fmt.Errorf("failed to execute migration statement in %s: %v", file, err)
			}
		}

		log.Printf("Successfully executed migration: %s", filepath.Base(file))
	}

	log.Println("All migrations completed successfully")
	return nil
}
