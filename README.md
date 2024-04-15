# go-schnorrq

Schnorr signature on FourQ for Qubic

## Usage

### Signature generation

Signature generation is not fully implemented yet.\
Please check later.

### Signature verification

```go

package main

import "github.com/qubic/go-schnorrq"
import "fmt"

func _()  {
	
	//Fill with your data
	signature := [64]byte{}
	messageDigest := [32]byte{}
	publicKey := [32]byte{}
	
	err := schnorrq.Verify(publicKey, messageDigest, signature)

	if err != nil {
		fmt.Printf("Error: %s\n", err.Error())
	}
}
```


## TODO list

- [ ] Signature Generation
- [x] Signature Verification
- [ ] Tidy up code / tests

