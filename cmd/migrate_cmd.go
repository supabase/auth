package cmd

import (
	"database/sql"
	_ "embed"
	"log"

	"github.com/lopezator/migrator"
	"github.com/netlify/gotrue/conf"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

var migrateCmd = cobra.Command{
	Use:  "migrate",
	Long: "Migrate database strucutures. This will create new tables and add missing columns and indexes.",
	Run:  migrate,
}

//go:embed migrations/00_init_auth_schema.up.sql
var mig0init string

//go:embed migrations/20210710035447_alter_users.up.sql
var mig1 string

//go:embed migrations/20210722035447_adds_confirmed_at.up.sql
var mig2 string

//go:embed migrations/20210730183235_add_email_change_confirmed.up.sql
var mig3 string

//go:embed migrations/20210909172000_create_identities_table.up.sql
var mig4 string

//go:embed migrations/20210927181326_add_refresh_token_parent.up.sql
var mig5 string

//go:embed migrations/20211122151130_create_user_id_idx.up.sql
var mig6 string

//go:embed migrations/20211124214934_update_auth_functions.up.sql
var mig7 string

//go:embed migrations/20211202183645_update_auth_uid.up.sql
var mig8 string

//go:embed migrations/20220114185221_update_user_idx.up.sql
var mig9 string

//go:embed migrations/20220114185340_add_banned_until.up.sql
var mig10 string

//go:embed migrations/20220224000811_update_auth_functions.up.sql
var mig11 string

//go:embed migrations/20220323170000_add_user_reauthentication.up.sql
var mig12 string

//go:embed migrations/20220412150300_add_unique_idx.up.sql
var mig13 string

func migrate(cmd *cobra.Command, args []string) {
	globalConfig, err := conf.LoadGlobal(configFile)
	if err != nil {
		logrus.Fatalf("Failed to load configuration: %+v", err)
	}

	m, err := migrator.New(
		migrator.Migrations(
			&migrator.Migration{
				Name: "00_init_auth_schema.up.sql",
				Func: func(tx *sql.Tx) error {
					if _, err := tx.Exec(mig0init); err != nil {
						return err
					}
					return nil
				},
			},
			&migrator.Migration{
				Name: "20210710035447_alter_users.up.sql",
				Func: func(tx *sql.Tx) error {
					if _, err := tx.Exec(mig1); err != nil {
						return err
					}
					return nil
				},
			},
			&migrator.Migration{
				Name: "20210722035447_adds_confirmed_at.up.sql",
				Func: func(tx *sql.Tx) error {
					if _, err := tx.Exec(mig2); err != nil {
						return err
					}
					return nil
				},
			},
			&migrator.Migration{
				Name: "20210730183235_add_email_change_confirmed.up.sql",
				Func: func(tx *sql.Tx) error {
					if _, err := tx.Exec(mig3); err != nil {
						return err
					}
					return nil
				},
			},
			&migrator.Migration{
				Name: "20210909172000_create_identities_table.up.sql",
				Func: func(tx *sql.Tx) error {
					if _, err := tx.Exec(mig4); err != nil {
						return err
					}
					return nil
				},
			},
			&migrator.Migration{
				Name: "20210927181326_add_refresh_token_parent.up.sql",
				Func: func(tx *sql.Tx) error {
					if _, err := tx.Exec(mig5); err != nil {
						return err
					}
					return nil
				},
			},
			&migrator.Migration{
				Name: "20211122151130_create_user_id_idx.up.sql",
				Func: func(tx *sql.Tx) error {
					if _, err := tx.Exec(mig6); err != nil {
						return err
					}
					return nil
				},
			},
			&migrator.Migration{
				Name: "20211124214934_update_auth_functions.up.sql",
				Func: func(tx *sql.Tx) error {
					if _, err := tx.Exec(mig7); err != nil {
						return err
					}
					return nil
				},
			},
			&migrator.Migration{
				Name: "20211202183645_update_auth_uid.up.sql",
				Func: func(tx *sql.Tx) error {
					if _, err := tx.Exec(mig8); err != nil {
						return err
					}
					return nil
				},
			},
			&migrator.Migration{
				Name: "20220114185221_update_user_idx.up.sql",
				Func: func(tx *sql.Tx) error {
					if _, err := tx.Exec(mig9); err != nil {
						return err
					}
					return nil
				},
			},
			&migrator.Migration{
				Name: "20220114185340_add_banned_until.up.sql",
				Func: func(tx *sql.Tx) error {
					if _, err := tx.Exec(mig10); err != nil {
						return err
					}
					return nil
				},
			},
			&migrator.Migration{
				Name: "20220224000811_update_auth_functions.up.sql",
				Func: func(tx *sql.Tx) error {
					if _, err := tx.Exec(mig11); err != nil {
						return err
					}
					return nil
				},
			},
			&migrator.Migration{
				Name: "20220323170000_add_user_reauthentication.up.sql",
				Func: func(tx *sql.Tx) error {
					if _, err := tx.Exec(mig12); err != nil {
						return err
					}
					return nil
				},
			},
			&migrator.MigrationNoTx{
				Name: "20220412150300_add_unique_idx.up.sql",
				Func: func(db *sql.DB) error {
					if _, err := db.Exec(mig13); err != nil {
						return err
					}
					return nil
				},
			},
		),
	)
	if err != nil {
		log.Fatal(err)
	}

	// Open database connection
	db, err := sql.Open("pgx", globalConfig.DB.URL)
	if err != nil {
		log.Fatal(err)
	}

	// Migrate up
	if err := m.Migrate(db); err != nil {
		log.Fatal(err)
	}
}
