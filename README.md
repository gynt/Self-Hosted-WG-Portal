# Self-Hosted-WG-Portal
Simple self-hosted WireGuard Portal to manage peers using Python


## Usage
1. Set up two WireGuard interfaces. One interface to serve your vpn (e.g. 10.0.0.1). Another interface on a separate subnet to host your portal (e.g. 10.0.1.1).
2. Run as root:
```{r}
python -m diywgportal peers init
python -m diywgportal --config myconfig.conf
```
3. Add clients
```{r}
python -m diywgportal accounts --add gynt <yubico public id>
```
4. Visit the portal at the configured URL and use your YubiKey Yubico to authenticate
5. Install the received config on the client and you are allowed to access 10.0.0.0/24 (configurable).
