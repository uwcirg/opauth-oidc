# Opauth-Oidc
Opauth strategy for OpenID Connect authentication.

Opauth is a multi-provider authentication framework for PHP.

## Getting started
Install Opauth-Oidc:

    composer require opauth/oidc:*

## Strategy configuration

Required parameters:

```php
<?php
'Oidc' => array(
	'client_id' => 'YOUR CLIENT ID',
	'client_secret' => 'YOUR CLIENT SECRET'
)
```

Optional parameters:
`scope`, `state`
