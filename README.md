# mod_token_auth

Apache module to validate access through ciphered  token AES and DESede

```
TODO: By now I'm using DESede but it would be nice to make it dynamic
TODO: Try to make it work with AES

check this out
https://www.openssl.org/docs/manmaster/apps/enc.html

and this
openssl enc -aes-192-cbc -a -in text -e -nosalt -iv "30313233343536373839313233343536" -K "54686520666f78206a756d706564206f76657220746865206c617a7920646f67" -p
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

