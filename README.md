# nird-toolkit-auth-helper

## Installing nird-toolkit-auth-helper

### From source

```shell
$ go install github.com/UNINETTSigma2/nird-toolkit-auth-helper@latest
```

### Minimal kubeconfig

```yaml
apiVersion: v1
clusters:
- cluster:
    certificate-authority-data: LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSURORENDQWh5Z0F3SUJBZ0lVUzhyMlh2N1AxQkpuMk1KZ014ODRhK1dLNEpjd0RRWUpLb1pJaHZjTkFRRUwKQlFBd0lERWVNQndHQTFVRUF4TVZUa2xTUkMxVFVDQkxkV0psY201bGRHVnpJRU5CTUI0WERUSXhNVEF5TVRFdwpNVFF3TUZvWERUSTJNVEF5TURFd01UUXdNRm93SURFZU1Cd0dBMVVFQXhNVlRrbFNSQzFUVUNCTGRXSmxjbTVsCmRHVnpJRU5CTUlJQklqQU5CZ2txaGtpRzl3MEJBUUVGQUFPQ0FROEFNSUlCQ2dLQ0FRRUF3Q0VlVXZtVkF1a2gKV1ArdmFjaGVXSVQ0MFppRlhXQmdxVkxZaUhVUHMyYU9XTjd5Wit6S0M4VGdyOUdMbXY4NGh1MXZGN2txNjNuZwpuTGZXOXczY291L2lFeWdOdDNZWTZHNUwzc3dDcjNlR0NndVRSNkdkZXFkYlZCdU1oZHdnb3FDWTVpdXRkWUR5CjBscnNQV1hST0Y4VThoTmFadS9DeUFMM3ppcDErU1BPbmx3eklweUw0WnlqTllNUUlyTmNqdWlaZXZQMEk5UEsKbThqYTdCQStTN1o2b2c5blFjcGpjSXROOEV1a2RRNkJZbEpxR3FWbktPQUhSUzZBWU1TS0tNZnlsZGpPN25nbwpseHlKdzhrSVhaZEJjSTI3eEhzbGhqMUd5MTUyRmpibXUzclhZVWVKc3lwYmRmdUV5YUtxLzJIRkQ5c2tnUUF2Cis5R29Mc3RsbHdJREFRQUJvMll3WkRBT0JnTlZIUThCQWY4RUJBTUNBUVl3RWdZRFZSMFRBUUgvQkFnd0JnRUIKL3dJQkFqQWRCZ05WSFE0RUZnUVUwVlBjVGt1aTludlBnUm8rUkwycnRrTHdydDh3SHdZRFZSMGpCQmd3Rm9BVQowVlBjVGt1aTludlBnUm8rUkwycnRrTHdydDh3RFFZSktvWklodmNOQVFFTEJRQURnZ0VCQUF6VnFvRitkNWVICklKa2hsT1Nzc0d5ZCtMdGUxajFMc3NoMWJMbUl3OGN2aUJ2cExzZXM3R2FpTFYwVlM3Y0x1cngwYms3Z0pHNjIKMXVGZXhhNStaRnNZV0gzQWpnbEZZSDNueXB0bWR6dHY3bGZwczVlSGJrYk9RMHlXMk51eGZCanA3T0RhcSttUwo3VlF3azVITVdwKzNQZ2c4aVV6SjVJcHhXbGFFWXc0aEpZeGNtTkFiTXpHOUhnZDh6cVowSUpxN3RTQ2Z5S3RZCm9RZDNqZENnVjk1MWFGUEFqMWI5aWtZSGZpT0YyS2VjMEZuUThlNFpUc2hraEREWSt2QXBBZllWR3ArU2FlWjYKZVoyY3dwN281aWxTWXRkdHBCL3FnUTdKTjEweEMvNWFVRXJTN2hvdDFTbTZDMW51UWRJRXJiUUU0YUM3SS91ZApRYmpkZG40d29Kaz0KLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQ==
    server: https://158.39.201.172:8443/
  name: bgo
users:
- name: bgo-user
  user:
    exec:
      apiVersion: client.authentication.k8s.io/v1beta1
      args:
      - login
      command: nird-toolkit-auth-helper
      env: null
      provideClusterInfo: true
contexts:
- context:
    cluster: bgo
    user: bgo-user
  name: bgo
```

```shell
$ kubectl config use-context bgo
$ kubectl get ns
```
