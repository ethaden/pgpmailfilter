package pgpmailfilterlib

import (
	"bytes"
	"fmt"
	"io"
	"log"
	"mime"
	"net/mail"
	"os"
	"strings"

	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/packet"
)

type CryptedMail struct {
	encrypted        mail.Message
	decrypted        mail.Message
	signatureChecked bool
	signatureValid   bool
}

type PgpMailFilter struct {
	entityList openpgp.EntityList
}

func (p PgpMailFilter) GetKeyring() openpgp.EntityList {
	return p.entityList
}

// Create a MailFilter struct by reading an arbitrary number of keyrings from the provided readers
func (mailFilter *PgpMailFilter) AddKeys(keyringReaders ...io.Reader) error {
	for _, reader := range keyringReaders {
		keyringContent, readErr := io.ReadAll(reader)
		if readErr != nil {
			return readErr
		}
		keyringBufferReader := bytes.NewReader(keyringContent)
		var entityList openpgp.EntityList
		var keyringErr error
		entityList, keyringErr = openpgp.ReadKeyRing(keyringBufferReader)
		if keyringErr != nil {
			keyringBufferReader.Seek(0, io.SeekStart)
			entityList, keyringErr = openpgp.ReadArmoredKeyRing(keyringBufferReader)
			if keyringErr != nil {
				return keyringErr
			}
		}
		mailFilter.entityList = append(mailFilter.entityList, entityList...)
	}
	return nil
}

func (m PgpMailFilter) Decrypt(reader io.Reader) (decryptedText []byte, hasSignature bool, signatureValid bool, err error) {
	config := &packet.Config{}
	messageDetails, msgErr := openpgp.ReadMessage(reader, m.GetKeyring(), nil, config)
	if msgErr != nil {
		err = msgErr
		return
	}
	decryptedText, readErr := io.ReadAll(messageDetails.LiteralData.Body)
	if readErr != nil {
		err = readErr
		return
	}
	hasSignature = messageDetails.IsSigned
	if hasSignature {
		signatureValid = (messageDetails.SignatureError == nil)
	}
	return
}

// Checks whether or not the signature is
func (m PgpMailFilter) CheckSignature(plainTextReader io.Reader, signatureReader io.Reader) (signatureOk bool, signer *openpgp.Entity, err error) {
	// It is unknown whether or not the signature is armored. Thus we cache both plainText and signature and try both validation methods
	// If one is successful, "signatureOk==true" is returned
	plainTextBuffer, plainReadErr := io.ReadAll(plainTextReader)
	if plainReadErr != nil {
		err = plainReadErr
		return
	}
	plainTextBufferReader := bytes.NewReader(plainTextBuffer)
	signatureBuffer, signatureReadErr := io.ReadAll(signatureReader)
	if signatureReadErr != nil {
		err = signatureReadErr
		return
	}
	signatureBufferReader := bytes.NewReader(signatureBuffer)
	signer, err = openpgp.CheckDetachedSignature(m.GetKeyring(), plainTextBufferReader, signatureBufferReader)
	if err != nil {
		return
	}
	// plainTextBufferReader.Seek(0, io.SeekStart)
	return
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
