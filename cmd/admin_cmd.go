package cmd

import (
	"github.com/gofrs/uuid"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/supabase/auth/internal/conf"
	"github.com/supabase/auth/internal/models"
	"github.com/supabase/auth/internal/storage"
)

var autoconfirm, isAdmin bool
var audience string

func getAudience(c *conf.GlobalConfiguration) string {
	if audience == "" {
		return c.JWT.Aud
	}

	return audience
}

func adminCmd() *cobra.Command {
	var adminCmd = &cobra.Command{
		Use: "admin",
	}

	adminCmd.AddCommand(&adminCreateUserCmd, &adminDeleteUserCmd)
	adminCmd.PersistentFlags().StringVarP(&audience, "aud", "a", "", "Set the new user's audience")

	adminCreateUserCmd.Flags().BoolVar(&autoconfirm, "confirm", false, "Automatically confirm user without sending an email")
	adminCreateUserCmd.Flags().BoolVar(&isAdmin, "admin", false, "Create user with admin privileges")

	return adminCmd
}

var adminCreateUserCmd = cobra.Command{
	Use: "createuser",
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) < 3 {
			logrus.Fatal("Not enough arguments to createuser command. Expected at least email, password and organization_id values")
			return
		}

		execWithConfigAndArgs(cmd, adminCreateUser, args)
	},
}

var adminDeleteUserCmd = cobra.Command{
	Use: "deleteuser",
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) < 2 {
			logrus.Fatal("Not enough arguments to deleteuser command. Expected at least ID or email and organization_id values")
			return
		}

		execWithConfigAndArgs(cmd, adminDeleteUser, args)
	},
}

func adminCreateUser(config *conf.GlobalConfiguration, args []string) {
	db, err := storage.Dial(config)
	if err != nil {
		logrus.Fatalf("Error opening database: %+v", err)
	}
	defer db.Close()

	aud := getAudience(config)
	id := uuid.Must(uuid.FromString(args[2]))

	if user, err := models.IsDuplicatedEmail(db, args[0], aud, nil, id, uuid.Nil); user != nil {
		logrus.Fatalf("Error creating new user: user already exists")
	} else if err != nil {
		logrus.Fatalf("Error checking user email: %+v", err)
	}

	user, err := models.NewUser("", args[0], args[1], aud, nil, id, uuid.Nil)
	if err != nil {
		logrus.Fatalf("Error creating new user: %+v", err)
	}

	err = db.Transaction(func(tx *storage.Connection) error {
		var terr error
		if terr = tx.Create(user, "project_id", "organization_role"); terr != nil {
			return terr
		}

		if len(args) > 2 {
			if terr = user.SetRole(tx, args[2]); terr != nil {
				return terr
			}
		} else if isAdmin {
			if terr = user.SetRole(tx, config.JWT.AdminGroupName); terr != nil {
				return terr
			}
		}

		if config.Mailer.Autoconfirm || autoconfirm {
			if terr = user.Confirm(tx); terr != nil {
				return terr
			}
		}
		return nil
	})
	if err != nil {
		logrus.Fatalf("Unable to create user (%s): %+v", args[0], err)
	}

	logrus.Infof("Created user: %s", args[0])
}

func adminDeleteUser(config *conf.GlobalConfiguration, args []string) {
	db, err := storage.Dial(config)
	if err != nil {
		logrus.Fatalf("Error opening database: %+v", err)
	}
	defer db.Close()

	id := uuid.Must(uuid.FromString(args[2]))
	user, err := models.FindUserByEmailAndAudience(db, args[0], getAudience(config), id, uuid.Nil)
	if err != nil {
		userID := uuid.Must(uuid.FromString(args[0]))
		user, err = models.FindUserByID(db, userID)
		if err != nil {
			logrus.Fatalf("Error finding user (%s): %+v", userID, err)
		}
	}

	if err = db.Destroy(user); err != nil {
		logrus.Fatalf("Error removing user (%s): %+v", args[0], err)
	}

	logrus.Infof("Removed user: %s", args[0])
}
