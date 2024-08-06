# nird-toolkit-auth-helper

## Installing nird-toolkit-auth-helper
You can download compiled binaries from the github release page.

### From source

```shell
$ go install github.com/UNINETTSigma2/nird-toolkit-auth-helper@latest
```

### Minimal kubeconfig

```yaml
apiVersion: v1
clusters:
- cluster:
    certificate-authority-data: c3ViamVjdD1DTj1sbWQtc3BtMDEuc2lnbWEyLm5vCmlzc3Vlcj1DTj1OSVJELVNQIEt1YmVybmV0ZXMgQ0EKLS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUU2ekNDQXRPZ0F3SUJBZ0lVVk9IKzVvbXpUOEg4NERESEUrSzFPSlVPOURZd0RRWUpLb1pJaHZjTkFRRU4KQlFBd0lERWVNQndHQTFVRUF4TVZUa2xTUkMxVFVDQkxkV0psY201bGRHVnpJRU5CTUI0WERUSXpNRE13TVRFMQpNamN3TUZvWERUTXpNRE13TVRBek1qY3dNRm93SGpFY01Cb0dBMVVFQXhNVGJHMWtMWE53YlRBeExuTnBaMjFoCk1pNXViekNDQVNJd0RRWUpLb1pJaHZjTkFRRUJCUUFEZ2dFUEFEQ0NBUW9DZ2dFQkFMRm04dlpKblJHd2loR2cKUTk5a1NpOExRQ3VScHdZNXZJR1k5MFNQNHJHV1lORjU2QlMrU2I1YzNYck9rSmg4MWQzZERTSWtpUzIxN0NpTwpVaTRIL08yYkFmeFBvT1NzOFdkWVBiaXlycis0YThnMW1sb1R2VmVWU29Lb0J2aWNNV1ZwaHlMOGFZUThxbXo5CjdXWDRCby9pcGdiWjcrMWpYVHB5YVJpWkRYNktxR1oycnJmTE9HSVFCVlpQTXlJZVdKVk1aU0NwQTI5Q2lYRXQKLytlVDA4Y0IzYWNWVjFOYWdBM0VUUWpEOWVvR1Z3U3pvaHlUSXVRME55bGdJT3BValpOTXRvaHlETHJhMnBHMQoyYzJ6OGd2cTNoSXJNKysvL1ZmREtoNTIzN3A2NndZcm94RnFYWmQzakU0dWxZQWVUL2xiVVowbWE5YWcxdWQyCkIzZXZRVGtDQXdFQUFhT0NBUjB3Z2dFWk1BNEdBMVVkRHdFQi93UUVBd0lGb0RBVEJnTlZIU1VFRERBS0JnZ3IKQmdFRkJRY0RBVEFNQmdOVkhSTUJBZjhFQWpBQU1CMEdBMVVkRGdRV0JCUmluWW9PUkduMnhxb2hwZmZucDhJTApFOEJIQ3pBZkJnTlZIU01FR0RBV2dCU0NxaXo5N1QyQStzSVM0bmNoTFh0SjhVVzZwakNCb3dZRFZSMFJCSUdiCk1JR1lnaE5zYldRdGMzQnRNREV1YzJsbmJXRXlMbTV2Z2hkaGNHbHpaWEoyWlhJdVkyeDFjM1JsY2k1c2IyTmgKYklJa2EzVmlaWEp1WlhSbGN5NWtaV1poZFd4MExuTjJZeTVqYkhWemRHVnlMbXh2WTJGc2doSmhjR2t1Ym1seQpaQzV6YVdkdFlUSXVibStIQkt3U0FBR0hCSjRrWm9pSEVQMnBKWXMrNE4yVkFBQUFBQUFBREt1SEVDQUJCd0JYCkR3QWxBQUFBQUFBQUFUWXdEUVlKS29aSWh2Y05BUUVOQlFBRGdnSUJBSHR1TkNlRkcxR2xsSnd5clpCNlBQRFIKa1cvSVlkOXlzUy9YWnRrYnBDNTFZbDJLQUJxNlkrYy9ITU5WWEwxNVpZQ0laVHFVZEZSK2tWVkJUcWZYSFhaegpLUVBRdFovK1UwYUt6TndxRCtVTDFhMXdpNWl2cU1zQ1duV3RqbmowakxjZWY1QTFXcUNCSnNGV3V5a3krY0lhClNDaEFpOWdiUXU3UHRmTG03Skt6VmNQV2JnK2xVWmQ0ZXVXMm0veHUzR1U1SHlkOWxHWmZUMjcybDFRVzdMakMKaU5aNGN5VzlOMVBDT1RoczA5OGN3YVNDNXM2M1JkZHlqVGJpc1oxRC9pRXFGTzVxR0F1VXlpWVNEN1RqTDRVdApzbGt0N1hqSHhmcFBEQ281ckcwK2tJeHNlZXB2YlRzTlpYUTRyaGFZTnRxM1NLVEJDVDZseTJLWGkzU1kwUVVQCkFkVEpxanhtM2ZmckVxSlg1ZnNoZDVGWkNoc0hMOGRoRWpQczZBSEk4N3gxU0pPZm5ySGdsVzg0cE5xZ2pQaEoKWkxkdHRTNUVzZUJ1SzNHemdTcHJ2ZllKanZHMndiL01uMENKblB2Vlh5d1BhREEwSStCSEhQaVZZem0xdVg5UgoyVWt1bzJPaUxZQkR6Unp5cEt6dDRHalJvYnRVQkxEUmdsd2o4eG9OenV4UEFDMkhVMUd0a0tjd1dWRlJiT1d0Ckt2TmpOV0hXZ1FodVo4bUpKczFRbWsxSkFIZmtsVUVwQ29zYmlRQXdPVE9OTG1CbkYxclNHNlVRbThueEJOcTkKR0FwTFB3ZWF4RStISkhTWDQ5Z2ZmMHJkR1JSU2ZWNWJjSG1uSFJSSEFKMk1ISEo2a3hyUWxyK0MwU0FwdVdOZQpBNGloL3l2VU1laFc4WVZyK3NjcAotLS0tLUVORCBDRVJUSUZJQ0FURS0tLS0tCnN1YmplY3Q9Q049bG1kLXNwbTAyLnNpZ21hMi5ubwppc3N1ZXI9Q049TklSRC1TUCBLdWJlcm5ldGVzIENBCi0tLS0tQkVHSU4gQ0VSVElGSUNBVEUtLS0tLQpNSUlFNnpDQ0F0T2dBd0lCQWdJVUVtWjZLR2lhTmZrL1pJaVZVQmlGdW5LWStna3dEUVlKS29aSWh2Y05BUUVOCkJRQXdJREVlTUJ3R0ExVUVBeE1WVGtsU1JDMVRVQ0JMZFdKbGNtNWxkR1Z6SUVOQk1CNFhEVEl6TURNd01URTEKTWpjd01Gb1hEVE16TURNd01UQXpNamN3TUZvd0hqRWNNQm9HQTFVRUF4TVRiRzFrTFhOd2JUQXlMbk5wWjIxaApNaTV1YnpDQ0FTSXdEUVlKS29aSWh2Y05BUUVCQlFBRGdnRVBBRENDQVFvQ2dnRUJBTkdQODEvd3FBTGg0bVdaCmd4QXpVbzhIaG1jVnZSdUxzR0o5YkxUZmVleCtLT21pOHYrakhOMXJkUHczcEhCT3N1YllkdUdhY2ZNcEFpeHcKZ2t5VmUwVDRDU0JCZGNwdUNVUTZMRDF1N0JKVGJ2a0dQbk5ocHRXcVdCWU52SVZldmtDRlZaSFpET0I0N1Y5TApNbWlITkh1TWZmVTZJUS92UjMveDlKL2JrL1EwMUxXY0lrajZpL29lNWo4M0d5ZHNGSmVsL3Q2SVphYXh5aGpMCmhPUy9sV1JFekM1bG5SM2tKYks2YncwdXFpQldwRCtrdmtud0NmNW9XRkRKV1R3SzhnRExZU0ZSdzZHZEdyelAKa09rQVV6eUJqbEZwWW1vWkFmeTVzbWVmQ2Q2TjNXOFlyZ0JqWlJlbFBkQXoydXo5OWZya1ZCcEp5T09xaDZqRApHWDBRMGZVQ0F3RUFBYU9DQVIwd2dnRVpNQTRHQTFVZER3RUIvd1FFQXdJRm9EQVRCZ05WSFNVRUREQUtCZ2dyCkJnRUZCUWNEQVRBTUJnTlZIUk1CQWY4RUFqQUFNQjBHQTFVZERnUVdCQlN6cXY2YS9OSFhZMjJJNDhRbDFmbWMKMW94cmx6QWZCZ05WSFNNRUdEQVdnQlNDcWl6OTdUMkErc0lTNG5jaExYdEo4VVc2cGpDQm93WURWUjBSQklHYgpNSUdZZ2hOc2JXUXRjM0J0TURJdWMybG5iV0V5TG01dmdoZGhjR2x6WlhKMlpYSXVZMngxYzNSbGNpNXNiMk5oCmJJSWthM1ZpWlhKdVpYUmxjeTVrWldaaGRXeDBMbk4yWXk1amJIVnpkR1Z5TG14dlkyRnNnaEpoY0drdWJtbHkKWkM1emFXZHRZVEl1Ym0rSEJLd1NBQUdIQko0a1pvbUhFUDJwSllzKzROMlZBQUFBQUFBQURLdUhFQ0FCQndCWApEd0FsQUFBQUFBQUFBVGN3RFFZSktvWklodmNOQVFFTkJRQURnZ0lCQUlqT2xrR0Yvam5wNDA3UE9xcndjbEI5CkhSWkJSdG42dyt4RzlQWHlFZ3RIcjFaV2w3aExxd3pCcXVPemxDMHBxUFlBNHJWVi9vRWRNSlVlTHdJa0NodkoKZXRzK1BEVXZyZUZ5U2xKYy8vNTBOTnpvbVM1WVlEa2NFdnU1N3g5MnBOYmVVVFF1MVI3Q0pVa0NYZTFtWU16KwpiMTFJY3REclFobFNsZjFBUFBMOWpoNm9lODV6dFVHNzFXUk9teWt5Y3VmNXBlUHVWNzZSUERPRXUxVmF5NzlyCmJhbWxNMzZDc2RkeTUvcEJWK1FjOXBscW1KaUFlS0YwbUdpZlVBWENVd1VHSXpoRGpCM2VrdTJHbU1JTmRHTjcKam9NRmd6MEVGQ2RWanlnRkpjM1hhaG1KbHlWQ1J2Y2phK3NBTFdVUDB6TmxHTTJZRmkyYkUrbW9aN2w2MDVCTApPczBRRVBrdElyTmZnakVMckpuUzFBNmlndHNzOWZyaWZoYzZMbXpQc3dyL3czZ2lBR0VvSkRxZWwvUmlGY0VOCnpsQzNUUVNkT3lJUUZTWjBGTFIrajJxMFF1bkxxVHRJbWZyZ2RwNmNXREs4a0R2Z1hjL0NGQzBSNVFST01qOHQKRnM0WDhBWkJHR05nZlBRb1g2aUM2T1dqTExhVVRnTUhITHRyd2hrdDdmM0piZ05UL0xBa1BCRFU0T3lYS3BJUgpIa1JYNnA4VmpnS2lmc01YWmYvdHVBRmRHbUtQbGY1WFdaT29yWTVyM0VOQzhwR3FOMXBUQmw2WEFjNnZxcU1CClI5VHRBc1Q1Qys3aXNBeWZHajZsVXV2OGZrNG5oSEUybVI5enlrMy8vZXJaZVpUcmhWcUp0b2hmSUh4emtPc0MKbm5nMzlOSjNkdk9IWU1kOElaT28KLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQpzdWJqZWN0PUNOPWxtZC1zcG0wMy5zaWdtYTIubm8KaXNzdWVyPUNOPU5JUkQtU1AgS3ViZXJuZXRlcyBDQQotLS0tLUJFR0lOIENFUlRJRklDQVRFLS0tLS0KTUlJRTZ6Q0NBdE9nQXdJQkFnSVVSWkpCYWJGMzRZRUVZQTgxZGlLU21SYVZqK2d3RFFZSktvWklodmNOQVFFTgpCUUF3SURFZU1Cd0dBMVVFQXhNVlRrbFNSQzFUVUNCTGRXSmxjbTVsZEdWeklFTkJNQjRYRFRJek1ETXdNVEUxCk1qY3dNRm9YRFRNek1ETXdNVEF6TWpjd01Gb3dIakVjTUJvR0ExVUVBeE1UYkcxa0xYTndiVEF6TG5OcFoyMWgKTWk1dWJ6Q0NBU0l3RFFZSktvWklodmNOQVFFQkJRQURnZ0VQQURDQ0FRb0NnZ0VCQU5Qd0ppQ2h6RXNlNmNFdwppbFkwc2poUlFiTk1hM2lxdE9Qb3oxTWVCblB1MXNrRWlZdGdwcXltZGgwSW9JVGxBdXJKY2xaTEtUcTJtVTFFCmdxK1JPTVZGdlh6NjMwbml1bU0yaFNkeXpkaHlMTUhKdnpwZVk2RXpFT2lVM1huTUtIemRGUmtjOW5aUmJaQ2sKR0ovaFRqS0s4U0F6anB6UEo1dXgvMjZsWFNzMWN3ZE80bDcxVjFNYUI3eEVJR3VnaDZTSjFVMlgveXJxWHA5ZQowM0ZoUUlWNGFkUUEvOWpHUkV1Rit0a1NwVXFFa25kVVYvdCtKT2ZuQlAvaGM3c3Z6c2NHNGNLYUFCT1JyNzhJCkUyM09IOGRqODBGcm9sYjgzU0hkajB3Y3dCMnV1QUNYL3VMZkk2MmloNUFIOWxWaHdCbGw3MHlwbWUvUERqRlkKNGI3WTZDa0NBd0VBQWFPQ0FSMHdnZ0VaTUE0R0ExVWREd0VCL3dRRUF3SUZvREFUQmdOVkhTVUVEREFLQmdncgpCZ0VGQlFjREFUQU1CZ05WSFJNQkFmOEVBakFBTUIwR0ExVWREZ1FXQkJUVWxwNlpub2tNaC8wSDd0dnplK3dVCmhaWkllakFmQmdOVkhTTUVHREFXZ0JTQ3Fpejk3VDJBK3NJUzRuY2hMWHRKOFVXNnBqQ0Jvd1lEVlIwUkJJR2IKTUlHWWdoTnNiV1F0YzNCdE1ETXVjMmxuYldFeUxtNXZnaGRoY0dselpYSjJaWEl1WTJ4MWMzUmxjaTVzYjJOaApiSUlrYTNWaVpYSnVaWFJsY3k1a1pXWmhkV3gwTG5OMll5NWpiSFZ6ZEdWeUxteHZZMkZzZ2hKaGNHa3VibWx5ClpDNXphV2R0WVRJdWJtK0hCS3dTQUFHSEJKNGtab3FIRVAycEpZcys0TjJWQUFBQUFBQUFES3VIRUNBQkJ3QlgKRHdBbEFBQUFBQUFBQVRnd0RRWUpLb1pJaHZjTkFRRU5CUUFEZ2dJQkFKVGlFOGtaOE1hTW5GRnZtUnV2TFFzaApmWlVQZ2VxU1cvWnFyTzdMZ3BJa1FJRzYwM1BLcG90Y2NFTnU0UEdjU282Z1ZsRUJINlp3SmoxbFZLRnM4SkhVCk9JRGlpWW1VOG9uTFZ2NU85TGNUNjlYMWFIS3ovQVVBbWdNaHNac095MVhzeFNzc0JDRjk4Vy9HZUxTUlppMTUKUXNnOUM4SG45VEVHWFozemZFZkF5K0tQUkZ2MHUrbXloWTl5elpiLzBsV20weVM2QjFCanlvWnNjTCtJNXNxSwpoVDJqempVeFh4d2NvSXorNzk3ZCt4bEh5Tlp3c2NTNTF0Q0ttZzEwNlpRV0R3T2hvZE9WNlYzWHNwUlo1amlWCm9sZ3YwYXc2bWl3T2NEZS9VcmRSTG1taVpXNkNoM2RIWUNXSVJiNVhib0wvZERQY0cwMFIrQXBDSFRRSEdLOG8KVzJWb1U1WStGNmdDL253VU45OGQzNGhlWnRvTjFObklhbytxenZ1M0J6TEZrODhxOW1pVXl0TlpnaGdiVjlBYwo0cFU1QzA4RFdYRDU0Q2VPTDV2bmZpQUEwSGlwMGhsTHZCRVhwaDJsMW1iWVZFK3hia0lId29Qd2ZtUURtb1VJCnlWdmZZRWhQdU96SmJSaldQS0dwY3E1TDZoZXdEYi8rZzBpNjdvbFZtM05oNjFQeGx3SWRIcXZCU0IyMVZ1UTQKdHZZZ3I5L3VsbTh5bTVoenJCcHVIbjhkSTZ0bDhNc1oyZVI5SG5NeFRqUkNXakVYcitteEtLQ3VxcDFGbzNtdQovREE1VGhoZDR2SEhieUF0UURKTXdOYW4zT3NTQ1RrZHpkRlh0WXRuV0Jja0dlWHc3aS9sTDdLQnFOVTBBbFg5CnZaTHV4dUF1TDJRdENRZzVyT1poCi0tLS0tRU5EIENFUlRJRklDQVRFLS0tLS0KCg==
    server: https://api.nird.sigma2.no:8443
  name: nird-lmd
contexts:
- context:
    cluster: nird-lmd
    user: nird-toolkit-cli
  name: nird-lmd
current-context: nird-lmd
kind: Config
preferences: {}
users:
- name: nird-toolkit-cli
  user:
    exec:
      apiVersion: client.authentication.k8s.io/v1beta1
      args:
      - login
      - --client-id
      - nird-toolkit-cli
      command: nird-toolkit-auth-helper
      env: null
      installHint: |-
        nird-toolkit-auth-helper is required to authenticate to the current cluster. It can be installed:

        https://github.com/uninettsigma2/nird-toolkit-auth-helper
      interactiveMode: Always
      provideClusterInfo: true
```

```shell
$ kubectl config use-context nird-trd
$ kubectl get ns
```

