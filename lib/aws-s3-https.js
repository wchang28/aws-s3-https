var crypto = require('crypto')

var AWS_S3_HOST_NAME = 's3.amazonaws.com';
var HTTPS_PORT = 443;

function getHTTPDateString(date) {
	var wds = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'];
	var months = ["Jan","Feb","Mar","Apr","May","Jun","Jul","Aug","Sep","Oct","Nov","Dec"];
	var s = '';
	s = wds[date.getUTCDay()];
	s += ', ';
	var v = date.getUTCDate(); 
	s += (v < 10 ? '0': '') + v.toString();
	s += ' ';
	s += months[date.getUTCMonth()];
	s += ' ';
	s += date.getUTCFullYear();
	s += ' ';
	v = date.getUTCHours();
	s += (v < 10 ? '0': '') + v.toString();
	s += ':'
	v = date.getUTCMinutes();
	s += (v < 10 ? '0': '') + v.toString();
	s += ':'
	v = date.getUTCSeconds();
	s += (v < 10 ? '0': '') + v.toString();
	s += ' GMT';
	return s;
}

function getCanonicalizedResource(s3Params) {return '/' + encodeURI(s3Params.Bucket) + '/' + encodeURI(s3Params.Key);}

// http://docs.aws.amazon.com/AmazonS3/latest/dev/RESTAuthentication.html#ConstructingTheAuthenticationHeader
// Signature = Base64( HMAC-SHA1( YourSecretAccessKeyID, UTF-8-Encoding-Of( StringToSign ) ) );
function getSignature(StringToSign, AWSSecretAccessKey) {
	var hmac = crypto.createHmac('sha1', AWSSecretAccessKey);
	hmac.update(StringToSign, 'utf8');
	var Signature = hmac.digest('base64');
	return Signature;
}

function getAuthorizationHeaderValue(AWSAccessKeyId, Signature) {return 'AWS ' + AWSAccessKeyId + ":" + Signature;}

function AWSS3Https(AWSAccessKeyId, AWSSecretAccessKey) {

	this.getObjectHeadOptions = function(s3Params, date) {
		var method = 'HEAD';
		if (!date) date = new Date();
		var dateString = getHTTPDateString(date);
		var CanonicalizedAmzHeaders = '';
		var CanonicalizedResource = getCanonicalizedResource(s3Params);
		var StringToSign = method + '\n\n\n' + dateString + '\n' + CanonicalizedAmzHeaders+CanonicalizedResource;
		var Signature = getSignature(StringToSign, AWSSecretAccessKey);
		var options =
		{
			hostname: AWS_S3_HOST_NAME
			,port: HTTPS_PORT
			,path: CanonicalizedResource
			,method: method
			,headers:
			{
				'Date': dateString
				,'Authorization': getAuthorizationHeaderValue(AWSAccessKeyId, Signature)
			}
		};
		return options;
	};

	this.getObjectDeleteOptions = function(s3Params, date) {
		var method = 'DELETE';
		if (!date) date = new Date();
		var dateString = getHTTPDateString(date);
		var CanonicalizedAmzHeaders = '';
		var CanonicalizedResource = getCanonicalizedResource(s3Params);
		var StringToSign = method + '\n\n\n' + dateString + '\n' + CanonicalizedAmzHeaders+CanonicalizedResource;
		var Signature = getSignature(StringToSign, AWSSecretAccessKey);
		var options =
		{
			hostname: AWS_S3_HOST_NAME
			,port: HTTPS_PORT
			,path: CanonicalizedResource
			,method: method
			,headers:
			{
				'Date': dateString
				,'Authorization': getAuthorizationHeaderValue(AWSAccessKeyId, Signature)
			}
		};
		return options;
	};

	this.getObjectGetUrlAndOptions = function(s3Params) {
		var method = 'GET';
		var expirySeconds = Math.round(new Date().getTime()/1000) + 86400*365*20;
		var CanonicalizedAmzHeaders = '';
		var CanonicalizedResource = getCanonicalizedResource(s3Params);
		var StringToSign = method + '\n\n\n' + expirySeconds.toString() + '\n' + CanonicalizedAmzHeaders+CanonicalizedResource;
		var Signature = getSignature(StringToSign, AWSSecretAccessKey);
		var queryString = '?' + "AWSAccessKeyId=" + AWSAccessKeyId;
		queryString += '&' + 'Signature=' + encodeURIComponent(Signature);
		queryString +=  '&' + 'Expires=' + expirySeconds.toString();
		var path = CanonicalizedResource + queryString;
		var protocol = 'https';
		var url = protocol + '://' + AWS_S3_HOST_NAME +':'+ HTTPS_PORT.toString() + path;
		var options = {
			hostname: AWS_S3_HOST_NAME
			,port: HTTPS_PORT
			,path: path
			,method: method
		};
		return {url: url, options: options};
	};

	this.getObjectPutOptions = function(s3Params, contentType, contentLength, date) {
		var method = 'PUT';
		if (!date) date = new Date();
		var dateString = getHTTPDateString(date);
		var amzHeaders = {'x-amz-acl':'public-read', 'x-amz-server-side-encryption': 'AES256'};
		var CanonicalizedAmzHeaders = '';
		for (var fld in amzHeaders)
			CanonicalizedAmzHeaders += fld + ':' + amzHeaders[fld] + '\u000a';
		var CanonicalizedResource = getCanonicalizedResource(s3Params);
		var StringToSign = method + '\n\n' + contentType + '\n' + dateString + '\n' + CanonicalizedAmzHeaders+CanonicalizedResource;
		var Signature = getSignature(StringToSign, AWSSecretAccessKey);
		var options =
		{
			hostname: AWS_S3_HOST_NAME
			,port: HTTPS_PORT
			,path: CanonicalizedResource
			,method: method
			,headers:
			{
				'Content-Type': contentType
				,'Content-Length': contentLength
				,'Date': dateString
				,'Authorization': getAuthorizationHeaderValue(AWSAccessKeyId, Signature)
			}
		};
		for (var fld in amzHeaders)
			options.headers[fld] = amzHeaders[fld];
		return options;
	};
}

module.exports = AWSS3Https;