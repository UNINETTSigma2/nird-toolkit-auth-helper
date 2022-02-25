/*
Copyright © 2022 NAME HERE <EMAIL ADDRESS>

*/
package cmd

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	cv "github.com/nirasan/go-oauth-pkce-code-verifier"
	"github.com/pkg/browser"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"golang.org/x/oauth2"
)

type ExecCredentialStatus struct {
	Token               string `json:"token,omitempty"`
	ExpirationTimestamp string `json:"expirationTimestamp,omitempty"`
}

type ExecCredential struct {
	APIVersion string               `json:"apiVersion,omitempty"`
	Kind       string               `json:"kind,omitempty"`
	Status     ExecCredentialStatus `json:"status"`
}

var (
	clientID     string
	scopes       []string
	issuer       string
	accessToken  string
	refreshToken string
)

// randString returns a random string of size nByte
func randString(nByte int) (string, error) {
	b := make([]byte, nByte)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func setCallbackCookie(w http.ResponseWriter, r *http.Request, name, value string) {
	c := &http.Cookie{
		Name:     name,
		Value:    value,
		MaxAge:   int(time.Hour.Seconds()),
		Secure:   r.TLS != nil,
		HttpOnly: true,
	}
	http.SetCookie(w, c)
}

// loginCmd represents the login command
var loginCmd = &cobra.Command{
	Use:   "login",
	Short: "login helper function for kubectl",
	Long:  ``,
	PreRun: func(cmd *cobra.Command, args []string) {
		cmd.SetOutput(os.Stderr)
	},
	RunE: func(cmd *cobra.Command, args []string) error {
		cachedToken := viper.GetString(fmt.Sprintf("cache.%s.token", clientID))
		if cachedToken != "" {
			token := oauth2.Token{}
			if err := json.Unmarshal([]byte(cachedToken), &token); err != nil {
				log.Fatal(err)
			}
			cmd.Println("Token: ", token.AccessToken)
			cmd.Println("Expiration: ", token.Expiry)
			os.Exit(0)
		}
		ctx := context.Background()

		httpClient := &http.Client{}

		ctx = oidc.ClientContext(ctx, httpClient)

		provider, err := oidc.NewProvider(ctx, issuer)
		if err != nil {
			log.Fatal(err)
		}

		oidcConfig := &oidc.Config{
			ClientID: clientID,
		}
		verifier := provider.Verifier(oidcConfig)

		config := oauth2.Config{
			ClientID:    clientID,
			RedirectURL: "http://localhost:49999/callback",
			Endpoint:    provider.Endpoint(),
			Scopes:      scopes,
		}

		codeVerifier, _ := cv.CreateCodeVerifier()
		challenge := codeVerifier.CodeChallengeS256()

		http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			state, err := randString(16)
			if err != nil {
				http.Error(w, "Internal error", http.StatusInternalServerError)
				return
			}

			nonce, err := randString(16)
			if err != nil {
				http.Error(w, "Internal error", http.StatusInternalServerError)
				return
			}

			setCallbackCookie(w, r, "state", state)
			setCallbackCookie(w, r, "nonce", nonce)

			authCodeURL := config.AuthCodeURL(
				state,
				oidc.Nonce(nonce),
				oauth2.SetAuthURLParam("code_challenge", challenge),
				oauth2.SetAuthURLParam("code_challenge_method", "S256"),
			)

			http.Redirect(w, r, authCodeURL, http.StatusFound)
		})

		http.HandleFunc("/callback", func(w http.ResponseWriter, r *http.Request) {
			state, err := r.Cookie("state")
			if err != nil {
				http.Error(w, "state not found", http.StatusBadRequest)
				return
			}

			if r.URL.Query().Get("state") != state.Value {
				http.Error(w, "state did not match", http.StatusBadRequest)
				return
			}

			oauth2Token, err := config.Exchange(
				ctx,
				r.URL.Query().Get("code"),
				oauth2.SetAuthURLParam("code_verifier", codeVerifier.String()))
			if err != nil {
				http.Error(w, "Failed to exchange token: "+err.Error(), http.StatusInternalServerError)
				return
			}

			rawIDToken, ok := oauth2Token.Extra("id_token").(string)
			if !ok {
				http.Error(w, "No id_token field in oauth2 token.2", http.StatusInternalServerError)
				return
			}

			idToken, err := verifier.Verify(ctx, rawIDToken)
			if err != nil {
				http.Error(w, "Failed to verify ID Token: "+err.Error(), http.StatusInternalServerError)
				return
			}

			nonce, err := r.Cookie("nonce")
			if err != nil {
				http.Error(w, "nonce not found", http.StatusBadRequest)
				return
			}

			if idToken.Nonce != nonce.Value {
				http.Error(w, "nonce did not match", http.StatusInternalServerError)
				return
			}

			resp := struct {
				OAuth2Token   *oauth2.Token
				IDTokenClaims *json.RawMessage
			}{oauth2Token, new(json.RawMessage)}

			if err := idToken.Claims(&resp.IDTokenClaims); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}

			cached, err := json.Marshal(oauth2Token)
			if err == nil {
				viper.Set(fmt.Sprintf("cache.%s.token", clientID), string(cached))
				viper.SafeWriteConfig()
			}

			execCredential := &ExecCredential{
				APIVersion: "client.authentication.k8s.io/v1",
				Kind:       "ExecCredential",
				Status: ExecCredentialStatus{
					Token:               resp.OAuth2Token.AccessToken,
					ExpirationTimestamp: resp.OAuth2Token.Expiry.Format("2006-01-02T15:04:05Z07:00"),
				},
			}

			b, err := json.MarshalIndent(execCredential, "", "    ")
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			fmt.Println(string(b))

			defer func() {
				time.Sleep(2 * time.Second)
				os.Exit(0)
			}()

			cmd.Println("viper:", viper.ConfigFileUsed())
			viper.WriteConfigAs(viper.GetViper().ConfigFileUsed())
		})

		go func(url string) {
			browser.Stdout = os.Stderr
			if err := browser.OpenURL(url); err != nil {
				log.Fatal("Unable to open browser:", err.Error())
			}
		}("http://localhost:49999")

		log.Fatal(http.ListenAndServe(":49999", nil))
		return nil
	},
}

func init() {
	rootCmd.AddCommand(loginCmd)

	loginCmd.Flags().StringVar(&clientID, "client-id", "oidc-client-sample", "OIDC Client ID to use")
	viper.GetViper().BindPFlag("client-id", loginCmd.Flags().Lookup("client-id"))
	loginCmd.Flags().StringSliceVar(&scopes, "scopes", []string{"email", "profile", "openid", "offline"}, "OIDC scopes to request")
	viper.GetViper().BindPFlag("scopes", loginCmd.Flags().Lookup("scopes"))
	loginCmd.Flags().StringVar(&issuer, "issuer", "https://apps-auth.sigma2.no/", "OIDC Provider to use")
	viper.GetViper().BindPFlag("issuer", loginCmd.Flags().Lookup("issuer"))
}
