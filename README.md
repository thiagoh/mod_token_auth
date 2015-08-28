# mod_token_auth

Apache module to validate access through token

```
check this out
https://www.openssl.org/docs/manmaster/apps/enc.html
```

## Apache2 config

Add the following code to your apache to test the examples

```
  # Inside <Directory> or <Location> tags
  <Location "/images">
       SetHandler token-auth-handler
       #TokenAuthEnabled false
       TokenAuthEnabled on
       TokenAuthSecretKey "The fox jumped over the lazy dog"
       TokenAuthDuration 4 s
  </Location>

  # Or outsite it
  
 AddHandler token-auth-handler .secret
 TokenAuthEnabled on
 TokenAuthSecretKey "This key is private. Or you'd have some problems..."
 TokenAuthDuration 2 h

```

