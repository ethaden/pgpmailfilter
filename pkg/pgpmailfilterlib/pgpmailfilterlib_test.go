package pgpmailfilterlib_test

import (
	"os"
	"testing"

	"github.com/ethaden/pgpmailfilter/pkg/pgpmailfilterlib"
	"github.com/stretchr/testify/assert"
)

const senderPGPTestIdentityFilenamePublic = "../../test/pgp/Go-Test-User_0xDE878D50_public.asc"
const senderPGPTestIdentityFilenameSecret = "../../test/pgp/Go-Test-User_0xDE878D50_SECRET.asc"
const receiverPGPTestIdentityFilenamePublic = "../../test/pgp/Go-Test-User-Other_0x20EE335C_public.asc"
const receiverPGPTestIdentityFilenameSecret = "../../test/pgp/Go-Test-User-Other_0x20EE335C_SECRET.asc"

func TestReadFile(t *testing.T) {
	mail, readErr := pgpmailfilterlib.ReadFileOrStdin("../../test/simple-file.txt")
	assert.NoError(t, readErr)
	expectedValue := "Test\nTest2\nTest3\n"
	if mail != expectedValue {
		t.Errorf("Expected:\n'%x'\n\ngot:\n'%x'\n", expectedValue, mail)
	}
}

func TestNewPgpMailFilter(t *testing.T) {
	fileReader, readErr := os.Open(senderPGPTestIdentityFilenameSecret)
	assert.NoError(t, readErr)
	defer fileReader.Close()
	mailFilter, err := pgpmailfilterlib.NewPgpMailFilter(fileReader)
	assert.NoError(t, err)
	assert.NotNil(t, mailFilter.Keyring)
}

func TestEncodeDecodeMimeMail(t *testing.T) {
}

func TestReadStdin(t *testing.T) {
	origStdin := os.Stdin
	defer func() { os.Stdin = origStdin }()

	testFile, err := os.Open("../../test/simple-file.txt")
	assert.NoError(t, err)
	defer testFile.Close()
	os.Stdin = testFile

	mail, readErr := pgpmailfilterlib.ReadFileOrStdin("")
	assert.NoError(t, readErr)
	expectedValue := "Test\nTest2\nTest3\n"
	if mail != expectedValue {
		t.Errorf("Expected:\n'%x'\n\ngot:\n'%x'\n", expectedValue, mail)
	}
}
