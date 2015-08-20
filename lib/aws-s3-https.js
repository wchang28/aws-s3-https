var crypto = require('crypto');
var fs = require('fs');
var mime = require('mime');
var https = require('https');
var stream = require('stream');

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
	var me = this;

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
	
	function s3ParsmsEqual(s3ParamsSrc, s3ParamsDest) {return (s3ParamsSrc.Bucket === s3ParamsDest.Bucket && s3ParamsSrc.Key === s3ParamsDest.Key);}
	
	// onStreamCreated(err, readableStream, streamLength, fileType)
	function createReadableStreamImpl(createParams, onStreamCreated) {
		try	{
			if (createParams.type === 'fs') {
				var stats = fs.statSync(createParams.filePath);
				var fileSizeInBytes = stats["size"]
				var rs = fs.createReadStream(createParams.filePath);
				var contentType = mime.lookup(createParams.filePath);
				if (typeof onStreamCreated === 'function') onStreamCreated(null, rs, fileSizeInBytes, contentType);
			} else if (createParams.type === 'url') {
				var urlModule = require('url');
				var urlString = createParams.url;
				if (typeof urlString != 'string' || urlString.length == 0) throw "url not optional";
				var additionalOptions = createParams.additionalOptions;
				var parts = urlModule.parse(urlString);
				var protocol = parts['protocol'];
				protocol = protocol.substr(0, protocol.length - 1);
				var httpModule = require(protocol);
				var options = {
					hostname: parts['hostname']
					,port: (parts['port'] ? parseInt(parts['port']) : (protocol === 'https' ? 443 : 80))
					,path: parts['path']
					,method: "GET"
				};
				if (additionalOptions) {
					for (var fld in additionalOptions) {
						options[fld] = additionalOptions[fld]
					}
				}
				var req = httpModule.request(options, function(res) {
					if (res.statusCode != 200) {
						if (typeof onStreamCreated === 'function') onStreamCreated('http returns error code of ' + res.statusCode, null, null, null);
					}
					else {
						var contentType = res.headers['content-type'];
						if (typeof onStreamCreated === 'function') onStreamCreated(null, res, res.headers['content-length'], contentType);
					}
				});
				req.on('error', function(err) {
					if (typeof onStreamCreated === 'function') onStreamCreated(err, null, null, null);
				});
				req.end();
			} else if (createParams.type === 'string') {
				var textContent = createParams.textContent;
				var s = new stream.Readable();
				s._read = function noop() {}; // redundant? see update below
				s.push(textContent);
				s.push(null);
				if (typeof onStreamCreated === 'function') onStreamCreated(null, s, textContent.length, 'text/plain');
			} else {
				if (typeof onStreamCreated === 'function') onStreamCreated('unsupported stream type: ' + createParams.type, null, null, null);
			}
		} catch(e) {
			if (typeof onStreamCreated === 'function') onStreamCreated(e, null, null, null);
		}
	}
	// upload a file to S3 given a readable stream
	// onDone(err)
	this.putByReadableStream = function(s3Params, readableStream, streamLength, contentType, onDone) {
		var options = me.getObjectPutOptions(s3Params, contentType, streamLength);
		var req = https.request(options, function(res) {
			if (res.statusCode != 200) {
				res.setEncoding('utf8');
				var s = "";
				res.on('data', function(d) {s += d.toString()});
				res.on('end', function() {
					if (typeof onDone === 'function') onDone({statusCode: res.statusCode, msg: s});
				});
			} else {
				if (typeof onDone === 'function') onDone(null);
			}
		});
		req.on('error', function(e) {
			if (typeof onDone === 'function') onDone(e);
		});
		readableStream.pipe(req);		
	};
	// upload a file to S3 given a local file path
	// onDone(err)
	this.putByFilePath = function(s3Params, filePath, onDone) {
		createReadableStreamImpl({type: 'fs', filePath: filePath}, function(err, readableStream, streamLength, contentType) {
			if (err) {
				if (typeof onDone === 'function') onDone(err);
			} else
				me.putByReadableStream(s3Params, readableStream, streamLength, contentType, onDone);
		});
	};
	// upload a file to S3 given file's url link
	// onDone(err)
	this.putByUrl = function(s3Params, urlString, additionalOptions, onDone) {
		createReadableStreamImpl({type: 'url', url: urlString, additionalOptions: additionalOptions}, function(err, readableStream, streamLength, contentType) {
			if (err) {
				if (typeof onDone === 'function') onDone(err);
			} else
				me.putByReadableStream(s3Params, readableStream, streamLength, contentType, onDone);
		});
	};
	// upload a small text file to S3 given file's text context
	// onDone(err)
	this.putTextContent = function(s3Params, textContent, onDone) {
		createReadableStreamImpl({type: 'string', textContent: textContent}, function(err, readableStream, streamLength, contentType) {
			if (err) {
				if (typeof onDone === 'function') onDone(err);
			} else
				me.putByReadableStream(s3Params, readableStream, streamLength, contentType, onDone);
		});
	};
	// copy a file from a S3 location to another S3 location
	// onDone(err)
	this.fileCopy = function(s3ParamsSrc, s3ParamsDest, onDone) {
		if (s3ParsmsEqual(s3ParamsSrc, s3ParamsDest)) {
			if (typeof onDone === 'function') onDone(null);
		} else {
			var urlSrc = me.getObjectGetUrlAndOptions(s3ParamsSrc).url;
			me.putByUrl(s3ParamsDest, urlSrc, null, onDone);
		}
	};
	// delete a file from S3
	// onDone(err)
	this.fileDelete = function(s3Params, onDone) {
		var options = me.getObjectDeleteOptions(s3Params);
		var req = https.request(options, function(res) {
			if (Math.floor(res.statusCode/100.0) != 2) {
				res.setEncoding('utf8');
				var s = "";
				res.on('data', function(d) {s += d.toString()});
				res.on('end', function() {
					if (typeof onDone === 'function') onDone({statusCode: res.statusCode, msg: s});
				});
			} else {
				if (typeof onDone === 'function') onDone(null);
			}
		});
		req.on('error', function(e) {
			if (typeof onDone === 'function') onDone(e);
		});
		req.end();
	};
	// move a file in S3
	// onDone(err)
	this.fileMove = function(s3ParamsSrc, s3ParamsDest, onDone) {
		if (s3ParsmsEqual(s3ParamsSrc, s3ParamsDest)) {
			if (typeof onDone === 'function') onDone(null);
		} else {
			// copy the file first
			me.fileCopy(s3ParamsSrc, s3ParamsDest, function(err) {
				if (err) {	// file copy error
					if (typeof onDone === 'function') onDone(err);
				} else {
					// copy successful, delete the source
					me.fileDelete(s3ParamsSrc, function (err) {
						if (err) { // cannot delete the source, delete the dest to roll-back
							me.fileDelete(s3ParamsDest, function() {
								if (typeof onDone === 'function') onDone(err);
							});
						} else {	// source deleted
							if (typeof onDone === 'function') onDone(null);
						}
					});
				}
			});
		}
	};
	// download a file from S3 given a writeable stream
	// onDone(err)
	this.getByWriteableStream = function(s3Params, writableStream, onDone) {
		var options = me.getObjectGetUrlAndOptions(s3Params).options;
		var req = https.request(options, function(res) {
			if (res.statusCode != 200) {
				res.setEncoding('utf8');
				var s = "";
				res.on('data', function(d) {s += d.toString()});
				res.on('end', function() {
					if (typeof onDone === 'function') onDone({statusCode: res.statusCode, msg: s});
				});
			} else {
				writableStream.on('finish', function() {
					if (typeof onDone === 'function') onDone(null);
				});
				res.pipe(writableStream);
			}
		});
		req.on('error', function(e) {
			if (typeof onDone === 'function') onDone(e);
		});
		req.end();
	};
	// download a file from S3 given a local file path
	// onDone(err)
	this.getByFilePath = function(s3Params, filePath, onDone) {
		try {
			var ws = fs.createWriteStream(filePath);
			me.getByWriteableStream(s3Params, ws, onDone);
		} catch (e) {
			if (typeof onDone === 'function') onDone(e);
		}
	}
	// get the text content from a text file stored in S3
	// onDone(err, textContent)
	this.getTextContent = function(s3Params, onDone) {
		try {
			var ws = new stream.Writable();
			ws._write = function (chunk, encoding, callback) {
				if (typeof ws.__string !== 'string') ws.__string = '';
				ws.__string += chunk.toString('utf8');
				callback();
			};
			ws.str = function() {return ws.__string;}
			me.getByWriteableStream(s3Params, ws, function(err) {
				if (err) {
					if (typeof onDone === 'function') onDone(err, null);
				} else {
					if (typeof onDone === 'function') onDone(null, ws.str());
				}
			});
		} catch (e) {
			if (typeof onDone === 'function') onDone(e, null);
		}
	};
}

module.exports = AWSS3Https;