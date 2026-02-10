/*
Copyright © 2026 Sigma2 As
*/
package cmd

import (
	"bytes"
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
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	k8sjson "k8s.io/apimachinery/pkg/runtime/serializer/json"
	"k8s.io/client-go/pkg/apis/clientauthentication/install"
	"k8s.io/client-go/pkg/apis/clientauthentication/v1beta1"
)

var scheme = runtime.NewScheme()

const successPage string = `
<html>
<body>
<h1>Success</h1>
<p>You may close this window.</p>
</body>
</html>
`

func init() {
	install.Install(scheme)
}

var (
	clientID string
	scopes   []string
	issuer   string
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

// getValidCachedToken looks up and return a cached oauth2.Token
func getValidCachedToken(ctx context.Context, cid string, p *oidc.Provider) *oauth2.Token {
	cachedToken := viper.GetString(fmt.Sprintf("cache.%s.token", cid))
	if cachedToken != "" {
		// Try to decode cached token
		token := oauth2.Token{}
		if err := json.Unmarshal([]byte(cachedToken), &token); err != nil {
			return nil
		}

		// Check if token is expired
		if time.Now().After(token.Expiry) {
			return nil
		}

		_, err := p.UserInfo(ctx, oauth2.StaticTokenSource(&token))
		if err != nil {
			return nil
		}

		return &token
	}
	return nil
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

		// obj, _, err := exec.LoadExecCredentialFromEnv()
		// if err != nil {
		// 	log.Fatal(err)
		// }
		serializer := k8sjson.NewSerializerWithOptions(
			k8sjson.DefaultMetaFactory,
			scheme,
			scheme,
			k8sjson.SerializerOptions{
				Pretty: true,
				Yaml:   false,
				Strict: true,
			},
		)

		// credentials := obj.(*v1beta1.ExecCredential)

		// Setup OAuth2/OIDC configuration
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

		// Look up cached token and return immediately if possible
		token := getValidCachedToken(ctx, clientID, provider)
		if token != nil {

			expiration := metav1.NewTime(token.Expiry)
			credentials := &v1beta1.ExecCredential{}
			credentials.APIVersion = "client.authentication.k8s.io/v1beta1"
			credentials.Status = &v1beta1.ExecCredentialStatus{
				Token:               token.AccessToken,
				ExpirationTimestamp: &expiration,
			}

			buf := bytes.NewBufferString("")
			if err := serializer.Encode(credentials, buf); err == nil {
				fmt.Println(buf.String())
				return nil
			}
		}

		// No cached token
		stopCh := make(chan struct{}, 1)
		mux := http.NewServeMux()
		srv := &http.Server{
			Addr:    ":49999",
			Handler: mux,
		}

		codeVerifier, _ := cv.CreateCodeVerifier()
		challenge := codeVerifier.CodeChallengeS256()

		mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
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

		mux.HandleFunc("/callback", func(w http.ResponseWriter, r *http.Request) {
			// Verify state belongs to session
			state, err := r.Cookie("state")
			if err != nil {
				http.Error(w, "state not found", http.StatusBadRequest)
				return
			}

			if r.URL.Query().Get("state") != state.Value {
				http.Error(w, "state did not match", http.StatusBadRequest)
				return
			}

			// Exchange code for token using PKCE
			oauth2Token, err := config.Exchange(
				ctx,
				r.URL.Query().Get("code"),
				oauth2.SetAuthURLParam("code_verifier", codeVerifier.String()))
			if err != nil {
				http.Error(w, "Failed to exchange token: "+err.Error(), http.StatusInternalServerError)
				return
			}

			// Extract ID Token
			rawIDToken, ok := oauth2Token.Extra("id_token").(string)
			if !ok {
				http.Error(w, "No id_token field in oauth2 token.2", http.StatusInternalServerError)
				return
			}

			// Verify cryptographic integrity of token
			idToken, err := verifier.Verify(ctx, rawIDToken)
			if err != nil {
				http.Error(w, "Failed to verify ID Token: "+err.Error(), http.StatusInternalServerError)
				return
			}

			// Verify nonce to ensure this is not a replay attack.
			nonce, err := r.Cookie("nonce")
			if err != nil {
				http.Error(w, "nonce not found", http.StatusBadRequest)
				return
			}

			if idToken.Nonce != nonce.Value {
				http.Error(w, "nonce did not match", http.StatusInternalServerError)
				return
			}

			// Build response for kubectl
			resp := struct {
				OAuth2Token   *oauth2.Token
				IDTokenClaims *json.RawMessage
			}{oauth2Token, new(json.RawMessage)}

			if err := idToken.Claims(&resp.IDTokenClaims); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}

			expiration := metav1.NewTime(oauth2Token.Expiry)
			credentials := &v1beta1.ExecCredential{}
			credentials.APIVersion = "client.authentication.k8s.io/v1beta1"
			credentials.Status = &v1beta1.ExecCredentialStatus{
				Token:               oauth2Token.AccessToken,
				ExpirationTimestamp: &expiration,
			}

			buf := bytes.NewBufferString("")
			if err := serializer.Encode(credentials, buf); err != nil {
				http.Error(w, "Unable to encode credentials", http.StatusInternalServerError)
				return
			}
			// Write credential status to stdout, consumed by kubectl
			fmt.Println(buf.String())

			// Update cache
			cached, err := json.Marshal(oauth2Token)
			if err == nil {
				viper.Set(fmt.Sprintf("cache.%s.token", clientID), string(cached))
			}
			viper.WriteConfigAs(viper.GetViper().ConfigFileUsed())

			// Show user success page
			w.Header().Add("Content-Type", "text/html")
			w.Write([]byte(successPage))

			// Send close signal to HTTP server
			stopCh <- struct{}{}
		})

		// Launch HTTP server
		go func() {
			if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				log.Fatal(err)
			}
		}()

		// Launch browser
		go func(url string) {
			browser.Stdout = os.Stderr
			if err := browser.OpenURL(url); err != nil {
				cmd.Printf("Unable to open browser, please visit %s to complete authentication", url)
			}
		}("http://localhost:49999")

		// Wait for close signal
		<-stopCh

		// Shutdown HTTP server
		if err := srv.Shutdown(ctx); err != nil {
			log.Fatal("Server shutdown failed")
		}

		return nil
	},
}

func init() {
	rootCmd.AddCommand(loginCmd)

	loginCmd.Flags().StringVar(&clientID, "client-id", "oidc-client-public", "OIDC Client ID to use")
	viper.GetViper().BindPFlag("client-id", loginCmd.Flags().Lookup("client-id"))
	loginCmd.Flags().
		StringSliceVar(&scopes, "scopes", []string{"email", "profile", "openid"}, "OIDC scopes to request")
	viper.GetViper().BindPFlag("scopes", loginCmd.Flags().Lookup("scopes"))
	loginCmd.Flags().StringVar(&issuer, "issuer", "https://apps-auth.sigma2.no/", "OIDC Provider to use")
	viper.GetViper().BindPFlag("issuer", loginCmd.Flags().Lookup("issuer"))
}
