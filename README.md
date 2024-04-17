# go-schnorrq

Schnorr signature on FourQ for Qubic

## Usage

> **Important:** Note that, in the context of Qubic, **subSeed** does **NOT** mean **private key**!  
> Key generation goes in this order:  
> `seed -> subSeed -> privateKey -> publicKey`  
> For more information on generating the different key types in Go see **[go-node-connector/wallet.go](https://github.com/qubic/go-node-connector/blob/main/types/wallet.go)**.  

### Signature generation

```go

package main

import "github.com/qubic/go-schnorrq"
import "fmt"

func _()  {
	
	// Fill with your data
	var subSeed [32]byte
	var publicKey [32]byte
	var message [32]byte
	
	singature, err := schnorrq.Sign(subSeed, publicKey, message)
	if err != nil {
		fmt.Printf("Error: %s\n", err.Error())
	}
}
```

### Signature verification

```go

package main

import "github.com/qubic/go-schnorrq"
import "fmt"

func _()  {
	
	// Fill with your data
	signature := [64]byte{}
	messageDigest := [32]byte{}
	publicKey := [32]byte{}
	
	err := schnorrq.Verify(publicKey, messageDigest, signature)
	if err != nil {
		fmt.Printf("Error: %s\n", err.Error())
	}
}
```


## Roadmap

- [x] Signature Generation
- [x] Signature Verification
- [x] Tidy up code / tests
- [ ] Move order package somewhere else?

