package main

import (
	"crypto/tls"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"strings"

	"golang.org/x/crypto/acme/autocert"
)

type response struct {
	Status   int  `json:"Status"`
	TC       bool `json:"TC"`
	RD       bool `json:"RD"`
	RA       bool `json:"RA"`
	AD       bool `json:"AD"`
	CD       bool `json:"CD"`
	Question []struct {
		Name string `json:"name"`
		Type int    `json:"type"`
	} `json:"Question"`
	Answer []struct {
		Name string `json:"name"`
		Type int    `json:"type"`
		TTL  int    `json:"TTL"`
		Data string `json:"data"`
	} `json:"Answer"`
}

func parseText(txt string) (string, string, error) {
	txt = strings.Trim(txt, " ")
	chunks := strings.Split(txt, " ")

	if len(chunks) < 2 {
		return "", "", errors.New("Missing required args [type name]")
	}

	return strings.ToUpper(strings.Trim(chunks[0], " ")), strings.Trim(chunks[1], " "), nil
}

func handle1111(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.NotFound(w, r)
		return
	}

	text := r.PostFormValue("text")
	t, name, err := parseText(text)

	if err != nil {
		w.Write([]byte(fmt.Sprint(err)))
		return
	}

	res, err := http.Get(fmt.Sprintf("https://cloudflare-dns.com/dns-query?ct=application/dns-json&type=%s&name=%s", t, name))

	if err != nil {
		w.Write([]byte("Unknown Error"))
		return
	}

	defer res.Body.Close()

	decoder := json.NewDecoder(res.Body)
	var data response

	err = decoder.Decode(&data)

	if err != nil {
		w.Write([]byte("Unknown Error"))
		return
	}

	var resData []string

	for _, d := range data.Answer {
		resData = append(resData, d.Data)
	}

	w.Write([]byte(strings.Join(resData, ", ")))

}

func serverProd() {
	certManager := autocert.Manager{
		Prompt:     autocert.AcceptTOS,
		HostPolicy: autocert.HostWhitelist("www.paizelnut.com"), //Your domain here
		Cache:      autocert.DirCache("certs"),                  //Folder for storing certificates
	}

	server := &http.Server{
		Addr: ":https",
		TLSConfig: &tls.Config{
			GetCertificate: certManager.GetCertificate,
		},
	}

	http.HandleFunc("/1111", handle1111)

	go http.ListenAndServe(":http", certManager.HTTPHandler(nil))

	fmt.Print("Stating Prod server")
	log.Fatal(server.ListenAndServeTLS("", "")) //Key and cert are coming from Let's Encrypt
}

func serverDev() {
	http.HandleFunc("/1111", handle1111)

	fmt.Print("Stating Dev server")
	log.Fatal(http.ListenAndServe(":4545", nil))
}

func main() {
	dev := flag.Bool("dev", false, "use the dev server")

	flag.Parse()

	if *dev {
		serverDev()
	} else {
		serverProd()
	}
}
