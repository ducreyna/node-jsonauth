# Node.js JsonAuth


This module is back-end part, taking care of token generation. Thanks to this, you can generate a token from your payload object. Then, a hmac string is created with your own secret key (be careful to not insert it in the payload object which can be decoded).

The token is built in two parts, the first segment is a json object stringified and encoded in base64. That json object is free, you can put all you want inside (except your secret key of course). The second segment is the first one hashed with your secret key, it permits to sign your json object.


## Installation

You can git clone this repo with the following methods:

- `git clone https://github.com/ducreyna/node-jsonauth.git`

You can also add this project as a dependency in your nodejs project by editing the `package.json` file as follow:

```json
{
	"dependencies": {
		"json-auth": "git+https://github.com/ducreyna/node-jsonauth.git"
	}
}
```

## How to use ?

```javascript
var JsonAuth = require('json-auth');

var secretKey = "mySecretKey";
var auth = new JsonAuth(secretKey);

var payload = {
	key1: "value1",
	key2: "value2"
};

// Encoding
var token = auth.encode(payload);
// "xxxxxxxxxx.yyyyyyyyyyy"	x=> payload encoded in base64
//							y => signature (hmac of your payload with your secret key)

// Decoding
var decoded = auth.decode(token); // Returns the payload object decoded as above
```
