# go-sozu

A simple Go client for interacting with the **sozu** reverse proxy.

## Features

-   Lightweight and easy to use
-   Provides wrapper functions for common sozu API operations
-   Clean and idiomatic Go design

## Installation

``` bash
go get github.com/patrostkowski/go-sozu
```

## Usage

``` go
package main

import (
	"context"
	"fmt"
	"log"

	"github.com/patrostkowski/go-sozu/pkg/client"
)

func main() {
	c := client.New()

	resp, err := c.Status(context.Background())
	if err != nil {
		log.Fatalf("status failed: %v", err)
	}

	log.Println("status:", resp.GetStatus(), "msg:", resp.GetMessage(), "content:", fmt.Sprintf("%+v", resp.GetContent()))
}
```

## License

[Apache-2.0](LICENSE)
