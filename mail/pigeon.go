package mail

import (
	"bytes"
	"crypto"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/go-fed/httpsig"
)

const host = "https://pigeon.jewewe.com"

type PigeonMail struct {
	KeyId string
	Secret string
	contact Contact
}

type Contact struct {
	AppName     string `json:"app_name"`
	ShopName    string `json:"shop_name"`
	ShopEmail   string `json:"shop_email"`
	ShopDomain  string `json:"shop_domain"`
	CountryCode string `json:"country_code"`
}

type ContactResponse struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

func NewPigeon(keyId,secret string) PigeonMail {
	return PigeonMail{
		KeyId: keyId,
		Secret: secret,
	}
}


func (p PigeonMail) InstallContact(contact Contact) error {
	p.contact = contact
	return p.postRequest(host + "/contact/install")
}

func (p PigeonMail) UninstallContact(contact Contact) error {
	p.contact = contact
	return p.postRequest(host + "/contact/uninsatll")
}

func (p PigeonMail) postRequest(path string) error {
	client := &http.Client{}
	contactJson, _ := json.Marshal(p.contact)
	body := strings.NewReader(string(contactJson))
	req, err := http.NewRequest(http.MethodPost, host+path, body)
	if err != nil {
		return err
	}
	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("date", time.Now().UTC().Format(http.TimeFormat))
	if err := SignRequest(p.KeyId, p.Secret, req); err != nil {
		return err
	}
	req.Header["Signature"][0] = strings.Replace(req.Header["Signature"][0], "algorithm=\"hs2019\"", "algorithm=\"hmac-sha256\"", 1)

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	var response ContactResponse
	json.Unmarshal(respBody, &response)
	if response.Code != 0 {
		return errors.New(response.Message)
	}
	return nil
}

func SignRequest(APPKey string, APPSecret string, r *http.Request) error {
	privateKey := crypto.PrivateKey([]byte(APPSecret))
	prefs := []httpsig.Algorithm{httpsig.HMAC_SHA256}
	headersToSign := []string{"(request-target)", "date", "digest"}
	signer, _, err := httpsig.NewSigner(prefs, httpsig.DigestSha256, headersToSign, httpsig.Signature, 0)
	if err != nil {
		return err
	}
	bodyBytes, _ := io.ReadAll(r.Body)
	r.Body.Close() //  must close
	r.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
	return signer.SignRequest(privateKey, APPKey, r, bodyBytes)
}