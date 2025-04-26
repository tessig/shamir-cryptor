package main

import (
	"encoding/hex"
	"fmt"
	"log"
	"strconv"

	"github.com/spf13/cobra"
	"github.com/tessig/shamir-cryptor/internal/file"
	"github.com/tessig/shamir-cryptor/internal/shamir"
)

func main() {
	var rootCmd = &cobra.Command{Use: "secret"}

	var createCmd = &cobra.Command{
		Use:   "generate <parts> <threshold>",
		Short: "Generates a random 512 bit secret key and the shamir parts",
		Long:  "Generates a random 512 bit secret key in hexadecimal presentation and <parts> shamir parts from which at least <threshold> are required to restore the secret.",
		Args:  cobra.ExactArgs(2),

		RunE: func(cmd *cobra.Command, args []string) error {
			parts, threshold, err := parsePartsThreshold(args[0], args[1])
			if err != nil {
				return err
			}

			size, _ := cmd.Flags().GetInt("size")

			secret, keyParts, err := shamir.Create(parts, threshold, size)
			if err != nil {
				return fmt.Errorf("failed to create secret and parts: %w", err)
			}

			cmd.Printf("Secret: %s\n", hex.EncodeToString(secret))
			printParts(cmd, keyParts)

			return nil
		},
	}
	createCmd.Flags().IntP("size", "s", 64, "byte size of the key")

	var combineCmd = &cobra.Command{
		Use:   "restore <parts...>",
		Short: "Restores a secret from its shamir parts",
		Long:  "Restores a secret from its shamir parts. If you have not enough parts, you will still recieve a restored secret, but a wrong one.",
		Args:  cobra.MinimumNArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			shares, err := parseShares(args)
			if err != nil {
				return err
			}

			secret, err := shamir.Combine(shares)
			if err != nil {
				return fmt.Errorf("failed to reconstruct secret: %w", err)
			}

			cmd.Printf("Restored secret: %s", hex.EncodeToString(secret))

			return nil
		},
	}

	var encryptCmd = &cobra.Command{
		Use:   "encrypt <file> <parts> <threshold>",
		Short: "Encrypts a file with a random 512 bit secret key and prints the shamir parts",
		Long:  "Encrypts a file with a random 512 bit secret key and creates <parts> shamir parts from which at least <threshold> are required to decrypt the file.",
		Args:  cobra.ExactArgs(3),
		RunE: func(cmd *cobra.Command, args []string) error {
			fileName := args[0]

			parts, threshold, err := parsePartsThreshold(args[1], args[2])
			if err != nil {
				return err
			}

			secret, keyParts, err := shamir.Create(parts, threshold, 32)
			if err != nil {
				return fmt.Errorf("failed to create secret and parts: %w", err)
			}

			encFileName, err := file.EncryptFile(fileName, fileName, []byte(secret))
			if err != nil {
				return fmt.Errorf("failed to encrypt file %q: %w", fileName, err)
			}

			cmd.Printf("encrypted file to %q\n", encFileName)
			printParts(cmd, keyParts)

			return nil
		},
	}

	var decryptCmd = &cobra.Command{
		Use:   "decrypt <file> <parts...>",
		Short: "Decrypts a file from its shamir parts",
		Long:  "Decrypts a file from its shamir parts. If you have not enough parts, the file decryption will fail.",
		Args:  cobra.MinimumNArgs(3),
		RunE: func(cmd *cobra.Command, args []string) error {
			fileName := args[0]

			shares, err := parseShares(args[1:])
			if err != nil {
				return err
			}

			secret, err := shamir.Combine(shares)
			if err != nil {
				return fmt.Errorf("failed to reconstruct secret: %w", err)
			}

			decFileName, err := file.DecryptFile(fileName, fileName, secret)
			if err != nil {
				return fmt.Errorf("failed to decrypt file %q: %w", fileName, err)
			}

			cmd.Printf("decrypted file to %q\n", decFileName)

			return nil
		},
	}

	rootCmd.AddCommand(createCmd, combineCmd, encryptCmd, decryptCmd)
	if err := rootCmd.Execute(); err != nil {
		log.Fatal(err)
	}
}

func parsePartsThreshold(p, t string) (int, int, error) {
	parts, err := strconv.Atoi(p)
	if err != nil {
		return 0, 0, fmt.Errorf("parts must be an integer: %w", err)
	}

	threshold, err := strconv.Atoi(t)
	if err != nil {
		return 0, 0, fmt.Errorf("threshold must be an integer: %w", err)
	}

	return parts, threshold, nil
}

func parseShares(args []string) ([][]byte, error) {
	var shares = make([][]byte, len(args))

	for i, p := range args {
		var err error
		shares[i], err = hex.DecodeString(p)
		if err != nil {
			return nil, fmt.Errorf("part %d is not a valid hex key: %w", i, err)
		}
	}

	return shares, nil
}

func printParts(cmd *cobra.Command, parts [][]byte) {
	for i, p := range parts {
		cmd.Printf("Part %d: %s\n", i+1, hex.EncodeToString(p))
	}
}
