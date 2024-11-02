package main

import (
	//"bufio"
	"fmt"
	"net/http"
	"strconv"

	//"os"
	"strings"
)

var caesarCypherDict = map[string]string{
    "a": "d", "b": "e", "c": "f", "d": "g", "e": "h",
    "f": "i", "g": "j", "h": "k", "i": "l", "j": "m",
    "k": "n", "l": "o", "m": "p", "n": "q", "o": "r",
    "p": "s", "q": "t", "r": "u", "s": "v", "t": "w",
    "u": "x", "v": "y", "w": "z", "x": "a", "y": "b",
    "z": "c", "0": "3", "1": "4", "2": "5", "3": "6",
	"4": "7", "5": "8", "6": "9", "7": "0", "8": "1",
	"9": "2",
}

var letterToNum = map[rune]int{
    'A': 0, 'B': 1, 'C': 2, 'D': 3, 'E': 4, 'F': 5, 'G': 6, 'H': 7,
    'I': 8, 'J': 9, 'K': 10, 'L': 11, 'M': 12, 'N': 13, 'O': 14, 'P': 15,
    'Q': 16, 'R': 17, 'S': 18, 'T': 19, 'U': 20, 'V': 21, 'W': 22, 'X': 23,
    'Y': 24, 'Z': 25,
}

var numToLetter = map[int]rune{
    0: 'A', 1: 'B', 2: 'C', 3: 'D', 4: 'E', 5: 'F', 6: 'G', 7: 'H',
    8: 'I', 9: 'J', 10: 'K', 11: 'L', 12: 'M', 13: 'N', 14: 'O', 15: 'P',
    16: 'Q', 17: 'R', 18: 'S', 19: 'T', 20: 'U', 21: 'V', 22: 'W', 23: 'X',
    24: 'Y', 25: 'Z',
}

// handles shifting one char
func vigenereShift(plainChar, keyChar rune) rune {
    plainVal := letterToNum[plainChar]
    keyVal := letterToNum[keyChar]
    cipherVal := (plainVal + keyVal) % 26 // Wrap around with modulo
    return numToLetter[cipherVal]
}

// handles putting the keyword to plaintext then shifting with vigenereShift
func vigenereCipher(plaintext, keyword string) string {
	var cipherText string
	keywordLength := len(keyword)
	keywordIndex := 0 // track pos in the keyword

	for _, char := range plaintext {
		// only apply the cipher to alphabetic characters
		if char >= 'A' && char <= 'Z' {
			keyChar := rune(keyword[keywordIndex % keywordLength]) // Repeat keyword to match plaintext length
			cipherText += string(vigenereShift(char, keyChar))
			keywordIndex++
		} else if char == ' ' {
			cipherText += " "
		} else {
			// Add non-alphabetic characters as is
			cipherText += string(char)
		}
	}
	return cipherText
}

func vigenereDecrypt(plaintext, keyword string) string {
	var decryptedText string
	keywordLength := len(keyword)
	keywordIndex := 0

	for _, char := range plaintext {
		// Only decrypt letters
		if char >= 'A' && char <= 'Z' {
			keyChar := rune(keyword[keywordIndex % keywordLength])
			plainVal := letterToNum[char]
			keyval := letterToNum[keyChar]

			// Subtract the shift and wrap around if negative
			decryptedVal := (plainVal - keyval + 26) % 26
			decryptedText += string(numToLetter[decryptedVal])
			keywordIndex++
		} else if char == ' ' {
			decryptedText += " "
		} else {
			decryptedText += string(char) // keep non letters as is
		}
	}

	return decryptedText
}

func caesarCypherFunc(input string) string {
	var caeserOutput string

	for _, char := range input {
		if replacement, exists := caesarCypherDict[string(char)]; exists {
			caeserOutput += replacement
		} else if char == ' ' {
			caeserOutput += " "
		} else {
			caeserOutput += string(char)
		}
	}

	return caeserOutput
}

func caesarDecryptFunc(input string) string {
	// Create decryption map
	caeserDecryptDict := make(map[string]string)
	for k, v := range caesarCypherDict {
		caeserDecryptDict[v] = k
	}

	var decryptedOutput string

	// Decrypt input
	for _, char := range input {
		if original, exists := caeserDecryptDict[string(char)]; exists {
			decryptedOutput += original
		} else if char == ' ' {
			decryptedOutput += " "
		} else {
			decryptedOutput += string(char) // Keep non ciphered characters
		}
	}

	return decryptedOutput
}

func stringToBinary(s string) (binString string) {
	for _, c := range s {
		binString += fmt.Sprintf("%08b", c)
	}
	return
}

func binaryToString(binaryStr string) (string, error) {
	var result string

	// Split binary string into chunks of 8 bits
	for i := 0; i < len(binaryStr); i += 8 {
		if i + 8 > len(binaryStr) {
			return "", fmt.Errorf("Binary string is not a valid 8-bit sequence")
		}

		// Take 8 bits at a time
		byteStr := binaryStr[i : i+8]

		// Convert binary (base 2) string to int
		asciiValue, err := strconv.ParseInt(byteStr, 2, 64)
		if err != nil {
			return "", err
		}

		// Convert int to ascii and add to result
		result += string(asciiValue)
	}

	return result, nil
}

func cipherHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		r.ParseForm()
		text := r.FormValue("text")
		mode := r.FormValue("mode")
		text = strings.ToUpper(strings.TrimSpace(text))

		var result string
		switch mode {
		case "caesar":
			result = caesarCypherFunc(strings.ToLower(text))
		case "vigenere":
			result = strings.ToLower(vigenereCipher(text, "KEY"))
		case "binary":
			result = stringToBinary(text)
		case "caesar-decipher":
			result = caesarDecryptFunc(strings.ToLower(text))
		case "vigenere-decipher":
			result = strings.ToLower(vigenereDecrypt(text, "KEY"))
		case "binary-decipher":
			decodedText, err := binaryToString(text)
			if err != nil {
				result = "Invalid binary string"
			} else {
				result = strings.ToLower(decodedText)
			}
		default:
			result = "Invalid cipher mode selected"
		}

		fmt.Fprint(w, result)
	} else {
		http.ServeFile(w, r, "index.html")
	}
}

func main() {
	http.HandleFunc("/", cipherHandler)
	fmt.Println("Server started")
	http.ListenAndServe(":8080", nil)
}