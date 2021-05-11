package pgpmailfilterlib

import (
	"fmt"
	"io"
	"log"
	"mime"
	"net/mail"
	"os"
	"strings"

	"golang.org/x/crypto/openpgp"
)

type CryptedMail struct {
	encrypted        mail.Message
	decrypted        mail.Message
	signatureChecked bool
	signatureValid   bool
}

type PgpMailFilter struct {
	Keyring openpgp.EntityList
}

func NewPgpMailFilter(keyringReader io.Reader) (*PgpMailFilter, error) {
	mailFilter := new(PgpMailFilter)
	var keyringErr error
	mailFilter.Keyring, keyringErr = openpgp.ReadKeyRing(keyringReader)
	if keyringErr != nil {
		return nil, keyringErr
	}
	return mailFilter, nil
}

func ReadFileOrStdin(inputFile string) (string, error) {
	if inputFile != "" {
		content, err := os.ReadFile(inputFile)
		if err != nil {
			log.Fatal("Unable to read input file")
		}
		data := string(content)
		data = strings.ReplaceAll(data, "\r", "")
		return data, nil
	}
	data, err := io.ReadAll(os.Stdin)
	if err != nil {
		log.Fatal("Error while reading input from stdin: %w", err)
		return "", err
	}
	return string(data), nil
}

func ReadMessageBody() {

}

func HandleMail(inputFile string, outputFile string) error {
	content, err := ReadFileOrStdin(inputFile)
	if err != nil {
		return err
	}
	str_reader := strings.NewReader(content)
	msg, msg_err := mail.ReadMessage(str_reader)
	if msg_err != nil {
		return msg_err
	}
	mediaType, params, parse_err := mime.ParseMediaType(msg.Header.Get("Content-Type"))
	if parse_err != nil {
		return parse_err
	}
	fmt.Printf("%v\n", mediaType)
	fmt.Printf("%v\n", params)
	return nil
}
