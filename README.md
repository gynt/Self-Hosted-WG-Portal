# Self-Hosted-WG-Portal
Simple self-hosted WireGuard Portal to manage peers using Python


## Usage
1. Set up your WireGuard interface.
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
5. Install the received config on the client
