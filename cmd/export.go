package cmd

import (
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/sumanthkumarc/medusa/pkg/encrypt"
	"github.com/sumanthkumarc/medusa/pkg/vaultengine"

	"github.com/spf13/cobra"
)

func init() {
	rootCmd.AddCommand(exportCmd)
	exportCmd.PersistentFlags().StringP("format", "f", "yaml", "Specify the export format [yaml|json]")
	exportCmd.PersistentFlags().StringP("output", "o", "", "Write to file instead of stdout")
	exportCmd.PersistentFlags().BoolP("encrypt", "e", false, "Encrypt the exported Vault data")
	exportCmd.PersistentFlags().StringP("public-key", "p", "", "Location of the RSA public key")
	exportCmd.PersistentFlags().StringP("engine-type", "m", "kv2", "Specify the secret engine type [kv1|kv2]")
}

var exportCmd = &cobra.Command{
	Use:   "export [vault path]",
	Short: "Export Vault secrets as yaml",
	Long:  ``,
	Args:  cobra.MinimumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		path := args[0]
		vaultAddr, _ := cmd.Flags().GetString("address")
		vaultToken, _ := cmd.Flags().GetString("token")
		insecure, _ := cmd.Flags().GetBool("insecure")
		namespace, _ := cmd.Flags().GetString("namespace")
		engineType, _ := cmd.Flags().GetString("engine-type")
		doEncrypt, _ := cmd.Flags().GetBool("encrypt")
		exportFormat, _ := cmd.Flags().GetString("format")
		output, _ := cmd.Flags().GetString("output")

		engine, path := vaultengine.PathSplitPrefix(path)
		client := vaultengine.NewClient(vaultAddr, vaultToken, insecure, namespace)
		client.UseEngine(engine)
		client.SetEngineType(engineType)

		// var exportData vaultengine.Folder
		var err error
		var folders []vaultengine.Folder
		start := time.Now()

		if path == "/" {
			mounts := client.GetMounts()
			// var mounts = map[string]string{
			// 	"lastmile/":     "kv1",
			// 	"dse/":          "kv1",
			// 	"authplatform/": "kv1",
			// 	"consumer/":     "kv1",
			// }

			// This channel is used to send export data from goroutines.
			channel := make(chan (vaultengine.Folder))

			// Done is a channel to signal the main thread that all the mounts have been processed.
			done := make(chan (bool), 1)

			// Collate all incoming folders from the channel.
			go func() {
				for folder := range channel {
					folders = append(folders, folder)
				}

				// Signal the main thread that all the folders were added.
				done <- true
			}()

			var wg sync.WaitGroup
			wg.Add(len(mounts))

			// Create multiple parallel threads for each mount
			for path, Type := range mounts {

				go func(path string, Type string) {
					client.SetEngineType(Type)
					exportData, _ := client.FolderExport(path)
					if exportData != nil {
						channel <- exportData
					}
					//  Send empty key when sub-folders arent present.

					defer wg.Done()
				}(path, Type)
			}

			wg.Wait()
			close(channel)

			// Wait for collation of all the folders
			<-done
			close(done)

		} else {
			exportData, err := client.FolderExport(path)
			if err != nil {
				fmt.Println(err)
				return err
			}
			folders = append(folders, exportData)
		}

		// Convert export to json or yaml
		var data []byte
		switch exportFormat {
		case "json":
			data, err = vaultengine.ConvertToJSON(folders)
		case "yaml":
			data, err = vaultengine.ConvertToYaml(folders)
		default:
			fmt.Printf("Wrong format '%s' specified. Available formats are yaml and json.\n", exportFormat)
			err = errors.New("invalid export format")
		}

		if err != nil {
			fmt.Println(err)
			return err
		}

		fmt.Printf("Execution took %v\n", time.Since(start))

		if doEncrypt {
			publicKeyPath, _ := cmd.Flags().GetString("public-key")
			encryptedKey, encryptedData := encrypt.Encrypt(publicKeyPath, output, data)

			if output == "" {
				fmt.Println(string([]byte(encryptedData)))
				fmt.Println(string(encryptedKey))
			} else {
				// Write to file
				// First encrypted data
				err = vaultengine.WriteToFile(output, []byte(encryptedData))
				if err != nil {
					return err
				}
				err = vaultengine.AppendStringToFile(output, "\n")
				if err != nil {
					return err
				}
				// Then encrypted AES key
				err = vaultengine.AppendStringToFile(output, encryptedKey)
				if err != nil {
					return err
				}
				err = vaultengine.AppendStringToFile(output, "\n")
				if err != nil {
					return err
				}
			}
		} else {
			if output == "" {
				fmt.Println(string(data))
			} else {
				err = vaultengine.WriteToFile(output, data)
				if err != nil {
					return err
				}
			}
		}

		return nil
	},
}
