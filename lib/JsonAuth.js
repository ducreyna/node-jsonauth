// #####################################################################################################################
// ############################################### R E Q U I R E S #####################################################
// #####################################################################################################################

var crypto = require('crypto');

// #####################################################################################################################
// ################################################# C L A S S #########################################################
// #####################################################################################################################

/**
 * This class encodes/decodes a token. The token is built in two parts, the first segment is an object stringified and 
 * encoded in base64. That object is free, you can put all you want. The second segment is the first segment hashed with
 * your secret key, it permits to sign it (i.e. your payload object).
 *
 * @class JsonAuth
 * 
 * @param {String} key 	Key used for the hmac process.
 * 
 */
function JsonAuth (key) {
	/**
	* @member {String} The algorithm used for the hashing process.
	*/
	this.algorithm = "sha512";

	/**
	* @member {String} Key used for hmac computing.
	*/
	this.key = key;
}

// #####################################################################################################################
// ############################################### M E T H O D S #######################################################
// #####################################################################################################################

/**
 * @method encode
 *
 * @description This method encodes a payload object in base64, signs it with a hmac token and joins two segments. 
 * 							Thanks to this, you can pass an object signed in all exchanges and be sessionless for example
 *
 * @param  {Object} payload
 *
 * @return {String} The token based on the parameters.
 * 
 */
JsonAuth.prototype.encode = function (payload) {
	if(!this.key) {
		throw new Error("Require secret key");
	}
	if(typeof(payload) !== "object" || payload.length !== undefined) {
		throw new Error("Payload parameter must be an object");
	}

	var segments = [this._base64UrlEncode(JSON.stringify(payload))];
	segments.push(this._sign(segments[0]));

	return segments.join(".");
};

// #####################################################################################################################

/**
 * @method decode
 *
 * @description This method decodes a given token. If the signature is valid, it returns the payload decoded and parsed
 *
 * @param  {String} token
 *
 * @return {Object} Token's payload.
 * 
 */
JsonAuth.prototype.decode = function (token) {
	var segments = token.split(".");

	if(this._sign(segments[0]) !== segments[1]) {
		throw new Error("Signature checking failed");
	}

	return JSON.parse(this._base64UrlDecode(segments[0]));
};

// #####################################################################################################################

/**
 * @method _sign
 *
 * @description This method returns a string hashed from an input string
 * 
 * @param  {String} input
 * 
 * @return {String}	String hashed
 * 
 */
JsonAuth.prototype._sign = function (input) {
	var hmac = crypto.createHmac(this.algorithm, this.key);
	hmac.update(input);
	return hmac.digest("hex");
};

// #####################################################################################################################

/**
 * @method _base64UrlEncode
 *
 * @description Encode a string in base64
 * 
 * @param  {String}	input
 * 
 * @return {String} Input string encoded
 * 
 */
JsonAuth.prototype._base64UrlEncode = function (input) {
	return this._base64UrlEscape(new Buffer(input).toString('base64'));
};

// #####################################################################################################################

/**
 * @method _base64UrlEscape
 *
 * @description Escape characters having other meanings in a url
 * 
 * @param  {String} input
 * 
 * @return {String} Input string formated
 * 
 */
JsonAuth.prototype._base64UrlEscape = function (input) {
	return input.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
};

// #####################################################################################################################

/**
 * @method _base64UrlDecode
 *
 * @description Decode a string in base64
 * 
 * @param  {String}	input
 * 
 * @return {String} Input string decoded
 * 
 */
JsonAuth.prototype._base64UrlDecode = function (input) {
	return new Buffer(this._base64UrlUnescape(input), 'base64').toString();
};

// #####################################################################################################################

/**
 * @method _base64UrlUnescape
 *
 * @description Replace characters escaped in the string encoded
 * 
 * @param  {String} input
 * 
 * @return {String} Input string formated
 * 
 */
JsonAuth.prototype._base64UrlUnescape = function (input) {
	input += new Array(5 - input.length % 4).join('=');
	return input.replace(/\-/g, '+').replace(/_/g, '/');
};

// #####################################################################################################################
// ################################################# E X P O R T S #####################################################
// #####################################################################################################################

module.exports = JsonAuth;