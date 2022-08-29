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
    certificate-authority-data: LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSURORENDQWh5Z0F3SUJBZ0lVTVREV0xOL0o2L2VGMXlySUZyRHEvRjBuZFM0d0RRWUpLb1pJaHZjTkFRRUwKQlFBd0lERWVNQndHQTFVRUF4TVZUa2xTUkMxVFVDQkxkV0psY201bGRHVnpJRU5CTUI0WERUSXhNVEF5TWpBNApNak13TUZvWERUSTJNVEF5TVRBNE1qTXdNRm93SURFZU1Cd0dBMVVFQXhNVlRrbFNSQzFUVUNCTGRXSmxjbTVsCmRHVnpJRU5CTUlJQklqQU5CZ2txaGtpRzl3MEJBUUVGQUFPQ0FROEFNSUlCQ2dLQ0FRRUF0b1R0RXI1ZDdTL1IKL2p5N2xSWnllUjd0WkpMQXVYU3ZsYk1VS3hrWWRQWEVndXZTbkg1clJnVGRabzZ5SDFJdC9ERktqZWRBcXlEUwozUkdVR3pYV2xLZldUbFI4YVZyaUkyUHA5Qk1RMFhnSDdMTitucmlOcUJ5NGQrcjZKSEhrZGNxVysyME8vQXVPClZzZHRBdTRpSDEyLzdnaFdyRDFRSVFWTmdPckt5Z1ducWg4VGd2VTZ4RDdrQ0t1Tmthbk8vVWpLZ290K280blkKbjlKcmR3bHZ5djYxY1BYOEtzcEo2UjZoVnJKRi9uWlc2TFlOeXNJaFlVc1h2NEl2aHk3bnU5ZThNMzJsNXlZRwphTk9DWE1ybCtsU1MwT1pHTGRrbjZVSFVFZGUwdTZSaGx6RjZvKzNYVU1OMWU0d2hReFYzcXBDU01nUzIyL1U2Cmw1QyttREY4bVFJREFRQUJvMll3WkRBT0JnTlZIUThCQWY4RUJBTUNBUVl3RWdZRFZSMFRBUUgvQkFnd0JnRUIKL3dJQkFqQWRCZ05WSFE0RUZnUVUxc3QvOFpjV0hNdFJFYTlycWRIZjNGbStJaEl3SHdZRFZSMGpCQmd3Rm9BVQoxc3QvOFpjV0hNdFJFYTlycWRIZjNGbStJaEl3RFFZSktvWklodmNOQVFFTEJRQURnZ0VCQUU0UkhlZ3ExWVVLCjBnaVgxeDZybmwzcUNqTG1qM0xOUE9kUjlzcXZpNjdrZVRIRFhkRndnT0FzaURRbTgvL1I5M0VxZnFzRTB6RCsKWisxVlhwNGJFU0VyQ1h1dkk1T1d4YVFGczFvU2swSUMxUVdIVDk5S0tPYUxjalowL1hPSGtVTGFFbWlGVlkrVQpNNjdRd0d3UHFWY1djK1pVandBSUtEV0RLeVpVSzU5WFUzS3RwRWZqN2wxT2MxYTJjNEN6cSs0aHVKU05MeldpCjh4T0tKaEdxOE5nZVJDZXpWUmdNQTlXeHNGU2tNeEpOWjNJL28rZE55Y1ZZcUpXSURNRG5Qc0RxQ09XdUY5Vm0KRVFpSTFFUUhaT3U4WS9QQ0V0aGtzdHBYeFBxZUZlMEErTFZsT1lJUFh6NVRNcVoyVUsyN2JsNGgvSHdMN29nUQo4a0YxTXNaQWxHbz0KLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQ==
    server: https://158.39.201.42:8443/
  name: nird-dev
users:
- name: nird-dev
  user:
    exec:
      apiVersion: client.authentication.k8s.io/v1beta1
      args:
      - login
      - --client-id
      - oidc-client-public
      command: nird-toolkit-auth-helper
      env: null
      installHint: |-
        nird-toolkit-auth-helper is required to authenticate
        to the current cluster. It can be installed:

        https://github.com/uninettsigma2/nird-toolkit-auth-helper
      interactiveMode: Always
      provideClusterInfo: true
contexts:
- context:
    cluster: nird-dev
    user: nird-dev
  name: nird-dev
```

```shell
$ kubectl config use-context nird-dev
$ kubectl get ns
```
