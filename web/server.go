package main

import (
	"log"
	"net/http"
)

func main() {
	log.Println("Listening on :8083...")
	http.HandleFunc("/", serveFiles) // "/" matches everything (See ServeMux)
	log.Fatal(http.ListenAndServeTLS(":8083", "server.crt", "server.key", nil))
}

func serveFiles(w http.ResponseWriter, r *http.Request) {
	log.Printf("Request: %s\n", r.URL.Path)

	var filePath = r.URL.Path[1:] //remove slash
	if filePath == "" {
		filePath = "index.html"
	} else {
		files := []string{"app.js", "noble-ed25519.js"}
		supported := false
		for _, f := range files {
			if f == filePath {
				supported = true
				break
			}
		}
		if !supported {
			http.NotFound(w, r)
			return
		}
	}

	log.Printf("Serving: %s", filePath)
	http.ServeFile(w, r, filePath)
}

// Function that serves as a debugging tool/endpoint for checking ed25519
// implementations (currently only tests private key generation).
//
// // keyFromSeed uses /kfs (key from seed) as a testing/debugging endpoint.
// func keyFromSeed(w http.ResponseWriter, r *http.Request) {
// 	dig := ce.Hash(ce.Sha256, []byte(r.URL.Query().Get("seed")))
// 	log.Printf("Digest of seed: %s\n%X\n", dig, dig)
// 	pk := ed25519.NewKeyFromSeed(dig)
// 	b, err := json.Marshal(pk.Public())
// 	if err != nil {
// 		log.Println(err)
// 		return
// 	}
// 	pb, err := json.Marshal(pk)
// 	if err != nil {
// 		log.Println(err)
// 		return
// 	}

// 	obj := struct {
// 		PubKey  json.RawMessage `json:"pubkey"`
// 		PrivKey json.RawMessage `json:"privkey"`
// 		Hex     string          `json:"hex"`
// 	}{
// 		PubKey:  b,
// 		PrivKey: pb,
// 		Hex:     fmt.Sprintf("%X", pb),
// 	}
// 	log.Printf("Pub Length: %d\nPriv Length: %d\n", len(b), len(pb))
// 	b, err = json.Marshal(obj)
// 	if err != nil {
// 		log.Println(err)
// 		return
// 	}
// 	w.Write(b)
// }
