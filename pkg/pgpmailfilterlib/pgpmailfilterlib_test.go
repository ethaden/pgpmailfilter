package pgpmailfilterlib_test

import (
	"bytes"
	"os"
	"testing"

	"github.com/ethaden/pgpmailfilter/pkg/pgpmailfilterlib"
	"github.com/stretchr/testify/assert"
)

type testKey struct {
	publicFilename string
	nrOfPublicKeys int
	publicKeyIds   []uint64
	secretFilename string
	nrOfSecretKeys int
	secretKeyIds   []uint64
}

var testKeys = []testKey{
	{
		publicFilename: "../../test/pgp/keys/Go-Test-User_0xDE878D50_public.asc",
		nrOfPublicKeys: 1,
		publicKeyIds:   []uint64{0x265bbb5ade878d50},
		secretFilename: "../../test/pgp/keys/Go-Test-User_0xDE878D50_SECRET.asc",
		nrOfSecretKeys: 1,
		secretKeyIds:   []uint64{0x712b1801e2ca2ea2},
	},
	{
		publicFilename: "../../test/pgp/keys/Go-Test-User-Other_0x20EE335C_public.asc",
		nrOfPublicKeys: 1,
		publicKeyIds:   []uint64{0xd731b62720ee335c},
		secretFilename: "../../test/pgp/keys/Go-Test-User-Other_0x20EE335C_SECRET.asc",
		nrOfSecretKeys: 1,
		secretKeyIds:   []uint64{0x544f24b5c49d9ca7},
	},
}

type testFileSetEncrypted struct {
	filename  string
	armored   bool
	signed    bool
	signerId  uint64
	encrypted bool
}

type testFileSet struct {
	plaintextFilename string
	encryptedFiles    []testFileSetEncrypted
}

var testFileSets = []testFileSet{
	{
		plaintextFilename: "../../test/pgp/text/plaintext1.txt",
		encryptedFiles: []testFileSetEncrypted{
			{
				filename:  "../../test/pgp/text/plaintext1-encrypted.gpg",
				armored:   false,
				signed:    false,
				signerId:  0,
				encrypted: true,
			},
			{
				filename:  "../../test/pgp/text/plaintext1-encrypted.asc",
				armored:   true,
				signed:    false,
				signerId:  0,
				encrypted: true,
			},
			{
				filename:  "../../test/pgp/text/plaintext1-signed.gpg",
				armored:   false,
				signed:    true,
				signerId:  0x265bbb5ade878d50,
				encrypted: false,
			},
			{
				filename:  "../../test/pgp/text/plaintext1-signed.asc",
				armored:   true,
				signed:    true,
				signerId:  0x265bbb5ade878d50,
				encrypted: false,
			},
		},
		// encryptedTextFilenameArmored:       "../../test/pgp/text/plaintext1-encrypted.asc",
		// signedTextFilename:                 "../../test/pgp/text/plaintext1-signed.gpg",
		// signedTextFilenameArmored:          "../../test/pgp/text/plaintext1-signed.asc",
		// signedEncryptedTextFilename:        "../../test/pgp/text/plaintext1-signed-encrypted.gpg",
		// signedEncryptedTextFilenameArmored: "../../test/pgp/text/plaintext1-signed-encrypted.asc",
	},
}

func TestReadFile(t *testing.T) {
	mail, readErr := pgpmailfilterlib.ReadFileOrStdin("../../test/simple-file.txt")
	assert.NoError(t, readErr)
	expectedValue := "Test\nTest2\nTest3\n"
	if mail != expectedValue {
		t.Errorf("Expected:\n'%x'\n\ngot:\n'%x'\n", expectedValue, mail)
	}
}

func addKeyToPgpMailFilterFromFile(t *testing.T, mailFilter *pgpmailfilterlib.PgpMailFilter, key testKey, readSecretKey bool) error {
	initialEntityList := mailFilter.GetKeyring()
	var initialNrOfKeys = len(initialEntityList)
	var initialNrOfSecretKeys = len(initialEntityList.DecryptionKeys())
	var err error
	var fileReader *os.File
	if readSecretKey {
		fileReader, err = os.Open(key.secretFilename)
	} else {
		fileReader, err = os.Open(key.publicFilename)
	}
	if assert.NoError(t, err) {
		defer fileReader.Close()
		if assert.NoError(t, err) {
			err = mailFilter.AddKeys(fileReader)
			assert.NoError(t, err)
			entityList := mailFilter.GetKeyring()
			// Check that the exact number of public keys have been added
			assert.Equal(t, key.nrOfPublicKeys+initialNrOfKeys, len(entityList))
			assert.Equal(t, key.publicKeyIds[0], entityList[initialNrOfKeys].PrimaryKey.KeyId)
			if readSecretKey {
				// Check that the exact number of private keys have been added
				assert.Equal(t, key.nrOfSecretKeys+initialNrOfSecretKeys, len(entityList.DecryptionKeys()))
				for secretKeyInd, secretKey := range entityList.DecryptionKeys() {
					// Skip all pre-existing (initial) secret keys
					if secretKeyInd < initialNrOfSecretKeys {
						continue
					}
					assert.Equal(t, key.secretKeyIds[secretKeyInd-initialNrOfSecretKeys], secretKey.PrivateKey.KeyId)
				}
			} else {
				// Check that the NO (!) private keys have been added
				assert.Equal(t, initialNrOfSecretKeys, len(entityList.DecryptionKeys()))
			}
			return nil
		}
	}
	return err
}

func TestNewPgpMailFilterFromFile(t *testing.T) {
	mailFilterPublic := &pgpmailfilterlib.PgpMailFilter{}
	for _, key := range testKeys {
		err := addKeyToPgpMailFilterFromFile(t, mailFilterPublic, key, false)
		assert.NoError(t, err)
		assert.NotNil(t, mailFilterPublic)
	}
	mailFilterSecret := &pgpmailfilterlib.PgpMailFilter{}
	for _, key := range testKeys {
		err := addKeyToPgpMailFilterFromFile(t, mailFilterSecret, key, true)
		assert.NoError(t, err)
		assert.NotNil(t, mailFilterSecret)
	}
}

func TestEncryptDecrypt(t *testing.T) {
	// Initialize mailFilter
	mailFilter := &pgpmailfilterlib.PgpMailFilter{}
	for _, key := range testKeys {
		err := addKeyToPgpMailFilterFromFile(t, mailFilter, key, true)
		assert.NoError(t, err)
		assert.NotNil(t, mailFilter)
	}
	for _, fileSet := range testFileSets {
		plainText, err := os.ReadFile(fileSet.plaintextFilename)
		assert.NoError(t, err)
		assert.NotEmpty(t, plainText)
		for _, encFileSet := range fileSet.encryptedFiles {
			fileReader, err := os.Open(encFileSet.filename)
			assert.NoError(t, err)
			defer fileReader.Close()
			// Special case: Only signature available, check against plaintext method!
			if encFileSet.signed && !encFileSet.encrypted {
				plainTextReader := bytes.NewReader(plainText)
				signatureOk, signer, err := mailFilter.CheckSignature(plainTextReader, fileReader)
				assert.NoError(t, err)
				assert.True(t, signatureOk)
				assert.Equal(t, encFileSet.signerId, signer.PrimaryKey.KeyId)
			} else {
				// Regular case: Encrypted with/without signature. Decrypt, then check signature if provided
				decryptedTest, hasSignature, signatureValid, err := mailFilter.Decrypt(fileReader)
				assert.NoError(t, err)
				assert.Equal(t, encFileSet.signed, hasSignature)
				if hasSignature {
					assert.True(t, signatureValid)
				} else {
					assert.False(t, signatureValid)
				}
				assert.Equal(t, plainText, decryptedTest)
			}
		}
	}
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
