# tpm_pcrtool
a simple commandline tool able to read and clear values of TPM's PCR, and extend its value with hash of given files.
Currently it is based on OpenSSL and libtspi and so only supports tpm 1.2, with future plan to support tpm2.

## Prerequisite
Some packages needed to installed.

### Debian GNU/Linux
<pre>
apt-get install libssl-dev libtspi-dev
</pre>
