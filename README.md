# tpm_pcrtool
a simple commandline tool able to read and clear values of TPM's PCR, and extend its value with hash of given files.

Now it supports both tpm 1.2 and tpm2, which it detected at runtime.

## Prerequisite
Some packages needed to installed.

### Debian GNU/Linux
<pre>
apt-get install libssl-dev libtspi-dev libsapi-dev libsapi-utils
</pre>
