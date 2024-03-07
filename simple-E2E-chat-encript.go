package main

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"math/big"
	"os"
	"strings"
)

var (
	p, _ = new(big.Int).SetString("112328702921012124042244738843257114515091404229646373580018117981221038084591298532396398963901805673847262405857097328876080856831366400913749301243997465109478021303696456872435882045909226035178678000686745837486053193312545273414183295439652451994427084819978229093036559704211923960555310652802384427745129", 10)
	g, _ = new(big.Int).SetString("2", 10)
)

func main() {
	fmt.Println("=== Simulasi Sesi Konsultasi Chat ===")

	// Pengguna A menghasilkan kunci pribadi dan publik
	privateA, publicA := generateKeyPair()

	// Pengguna B menghasilkan kunci pribadi dan publik
	privateB, publicB := generateKeyPair()

	// Pertukaran kunci publik antara Pengguna A dan Pengguna B
	sharedKeyA := calculateSharedKey(privateA, publicB)
	sharedKeyB := calculateSharedKey(privateB, publicA)

	// Kedua pengguna seharusnya memiliki kunci sesi yang sama
	fmt.Println("Shared Key A:", sharedKeyA)
	fmt.Println("Shared Key B:", sharedKeyB)

	// Simulasi Sesi Konsultasi Chat
	fmt.Println("\n=== Sesi Konsultasi Chat ===")

	go startChatSession("Pengguna A", sharedKeyA)
	startChatSession("Pengguna B", sharedKeyB)
}

// generateKeyPair menghasilkan kunci pribadi dan publik
func generateKeyPair() (*big.Int, *big.Int) {
	privateKey, _ := rand.Int(rand.Reader, p)
	publicKey := new(big.Int).Exp(g, privateKey, p)
	return privateKey, publicKey
}

// calculateSharedKey menghitung kunci sesi yang bersama
func calculateSharedKey(privateKey, publicKey *big.Int) *big.Int {
	sharedKey := new(big.Int).Exp(publicKey, privateKey, p)
	return sharedKey
}

// startChatSession memulai sesi konsultasi chat
func startChatSession(user string, sharedKey *big.Int) {
	scanner := bufio.NewScanner(os.Stdin)

	fmt.Printf("[%s] Masukkan pesan untuk konsultasi (Ketik 'exit' untuk keluar):\n", user)

	for scanner.Scan() {
		message := scanner.Text()

		if strings.ToLower(message) == "exit" {
			fmt.Printf("[%s] Konsultasi diakhiri.\n", user)
			break
		}

		encryptedMessage := encryptMessage(message, sharedKey)
		decryptedMessage := decryptMessage(encryptedMessage, sharedKey)

		fmt.Printf("[%s] Pesan Terenkripsi: %v\n", user, encryptedMessage)
		fmt.Printf("[%s] Pesan Terdekripsi: %v\n", user, decryptedMessage)
	}
}

// encryptMessage mengenkripsi pesan menggunakan AES dan kunci sesi
func encryptMessage(message string, key *big.Int) string {
	// Mengambil 16 byte pertama dari kunci sebagai kunci AES
	keyBytes := key.Bytes()[:16]

	block, err := aes.NewCipher(keyBytes)
	if err != nil {
		panic(err)
	}

	// Menggunakan GCM mode untuk enkripsi
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		panic(err)
	}

	// Membuat nonce yang unik
	nonce := make([]byte, aesGCM.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		panic(err)
	}

	// Mengenkripsi pesan
	ciphertext := aesGCM.Seal(nil, nonce, []byte(message), nil)

	// Menggabungkan nonce dengan ciphertext untuk kemudian disatukan dalam satu string
	ciphertextWithNonce := append(nonce, ciphertext...)

	return hex.EncodeToString(ciphertextWithNonce)
}

// decryptMessage mendekripsi pesan menggunakan AES dan kunci sesi
func decryptMessage(encryptedMessage string, key *big.Int) string {
	// Mengambil 16 byte pertama dari kunci sebagai kunci AES
	keyBytes := key.Bytes()[:16]

	block, err := aes.NewCipher(keyBytes)
	if err != nil {
		panic(err)
	}

	// Menggunakan GCM mode untuk dekripsi
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		panic(err)
	}

	// Mendekode string heksadesimal ke bentuk byte
	ciphertextWithNonce, err := hex.DecodeString(encryptedMessage)
	if err != nil {
		panic(err)
	}

	// Mengambil nonce dari ciphertextWithNonce
	nonce := ciphertextWithNonce[:aesGCM.NonceSize()]

	// Mengambil ciphertext dari ciphertextWithNonce
	ciphertext := ciphertextWithNonce[aesGCM.NonceSize():]

	// Mendekripsi pesan
	decryptedMessage, err := aesGCM.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		panic(err)
	}

	return string(decryptedMessage)
}
