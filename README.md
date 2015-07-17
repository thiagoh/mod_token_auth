# mod_token_auth

Apache module to validate access through token


## Apache2 config

Add the following code to your apache to test the examples

```

  <Location "/example">
      SetHandler example-handler
  </Location>

  AddHandler example-handler .doit

```
