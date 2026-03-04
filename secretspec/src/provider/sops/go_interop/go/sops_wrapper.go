package main

/*
#include <stdlib.h>
*/
import "C"
import (
	"os"
	"unsafe"
	"github.com/getsops/sops/v3/decrypt"
	"github.com/getsops/sops/v3/cmd/sops/formats"
)

//export DecryptData
func DecryptData(data *C.char, format *C.char) *C.char {
	goData := C.GoString(data)
	goFormat := C.GoString(format)

	cleartext, err := decrypt.Data([]byte(goData), goFormat)
	if err != nil {
		return C.CString("")
	}

	return C.CString(string(cleartext))
}

//export DecryptDataWithFormat
func DecryptDataWithFormat(data *C.char, inputFormat *C.char, outputFormat *C.char) *C.char {
	goData := C.GoString(data)
	// goInputFormat := C.GoString(inputFormat)
	goOutputFormat := C.GoString(outputFormat)

	// Convert string format to formats.Format
	var outputFmt formats.Format
	switch goOutputFormat {
	case "json":
		outputFmt = formats.Json
	case "yaml", "yml":
		outputFmt = formats.Yaml
	case "dotenv", "env":
		outputFmt = formats.Dotenv
	case "ini":
		outputFmt = formats.Ini
	case "binary":
		outputFmt = formats.Binary
	default:
		outputFmt = formats.Yaml // default to YAML
	}

	cleartext, err := decrypt.DataWithFormat([]byte(goData), outputFmt)
	if err != nil {
		return C.CString("")
	}

	return C.CString(string(cleartext))
}

//export DecryptFile
func DecryptFile(path *C.char, format *C.char) *C.char {
	goPath := C.GoString(path)
	goFormat := C.GoString(format)

	cleartext, err := decrypt.File(goPath, goFormat)
	if err != nil {
		return C.CString("")
	}

	return C.CString(string(cleartext))
}

//export DecryptFileWithEnv
func DecryptFileWithEnv(path *C.char, format *C.char, ageKeyFile *C.char, ageKey *C.char, kmsArn *C.char, awsProfile *C.char) *C.char {
	goPath := C.GoString(path)
	goFormat := C.GoString(format)

	// Set environment variables if provided
	if ageKeyFile != nil {
		goAgeKeyFile := C.GoString(ageKeyFile)
		if goAgeKeyFile != "" {
			os.Setenv("SOPS_AGE_KEY_FILE", goAgeKeyFile)
		}
	}

	if ageKey != nil {
		goAgeKey := C.GoString(ageKey)
		if goAgeKey != "" {
			os.Setenv("SOPS_AGE_KEY", goAgeKey)
		}
	}

	if kmsArn != nil {
		goKmsArn := C.GoString(kmsArn)
		if goKmsArn != "" {
			os.Setenv("SOPS_KMS_ARN", goKmsArn)
		}
	}

	if awsProfile != nil {
		goAwsProfile := C.GoString(awsProfile)
		if goAwsProfile != "" {
			os.Setenv("AWS_PROFILE", goAwsProfile)
		}
	}

	cleartext, err := decrypt.File(goPath, goFormat)
	if err != nil {
		return C.CString("")
	}

	return C.CString(string(cleartext))
}

//export DecryptFileWithAgeKey
func DecryptFileWithAgeKey(path *C.char, format *C.char, ageKeyFile *C.char) *C.char {
	goPath := C.GoString(path)
	goFormat := C.GoString(format)
	goAgeKeyFile := C.GoString(ageKeyFile)

	// Set the age key file environment variable
	if goAgeKeyFile != "" {
		os.Setenv("SOPS_AGE_KEY_FILE", goAgeKeyFile)
	}

	cleartext, err := decrypt.File(goPath, goFormat)
	if err != nil {
		return C.CString("")
	}

	return C.CString(string(cleartext))
}

//export GoFree
func GoFree(ptr *C.char) {
	C.free(unsafe.Pointer(ptr))
}

func main() {}
