package keyring

import (
	"fmt"
	"os"

	"golang.org/x/term"
)

// PromptFunc is a function used to prompt the user for a password.
type PromptFunc func(string) (string, error)

func TerminalPrompt(prompt string) (string, error) {
	_, err := fmt.Fprintf(os.Stderr, "%s: ", prompt)
	if err != nil {
		return "", err
	}

	b, err := term.ReadPassword(int(os.Stdin.Fd()))
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func FixedStringPrompt(value string) PromptFunc {
	return func(_ string) (string, error) {
		return value, nil
	}
}
