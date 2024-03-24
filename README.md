Windows SSPI Auth Burp Extension
============================

# Description
Uses windows SSPI to inject Authorize header built from your current windows login into all requests.
Mainly useful for environments where burps built-in NTLM settings and the Berserko extension doesn't work (e.g you can't generate a kerberos token using a password).

Note. Sending the Authorize header everywhere may not be a good idea.

Allows you to configure SNI too!

WARNING: Burp only shows the injected header when looking in Logger. This is likely to lead to confusion.

# TODO
- This doesn't negotiate. It just injects the header everywhere. Implement waiting for 401 and adapting based on the Www-Authenticate header.
- Canonicalization of SPN hostname is minimal and probably not good enough.