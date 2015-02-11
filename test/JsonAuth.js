var assert = require("assert");
var JsonAuth = require("../lib/JsonAuth.js");


describe("JsonAuth", function () {
	var auth = new JsonAuth();
	var payload = {
		key: "value",
		key2: "value2"
	};
	auth.key = "1234";
	var expToken = "eyJrZXkiOiJ2YWx1ZSIsImtleTIiOiJ2YWx1ZTIifQ.f7a4acea730f514c7d137e2ddc754b2e507e512412797e40fadc7bbec24c3f16a993300fcdc72718139e65e2e25cdf1f8f61674f18fdc76b73db89598bf7f675";


	it("Token encoding", function () {
		assert.strictEqual(auth.encode(payload), expToken);
	});

	it("Token decoding", function () {
		var decoded = auth.decode(expToken);

		assert.strictEqual(decoded.key, payload.key);
		assert.strictEqual(decoded.key2, payload.key2);
	});
});