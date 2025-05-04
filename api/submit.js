// api/submit.js
import crypto from 'crypto';
import axios from 'axios';
import querystring from 'querystring';
import url from 'url';
import multer from 'multer';
import nextConnect from 'next-connect';

const consumerKey = '2ff01625ff243c109e765d787c9ac0ca9c509d71302bc9888b930c4047b3ff02';
const consumerSecret = '06f6c64fb90b12cca30c7bc3fb71fdca978fa31cb3e135329610a9a2f4ac00e8';
const tokenId = 'c355e73e71fdb0c94b88ca91ec878b00c3b0ddee3837c4dfb6b32e9b90049dae';
const tokenSecret = '5af9e608cb52fc0a8d77d43cfaa0cdad5fa0aa3b87138813054265a84b596503';
const accountId = '3617444';
const scriptId = '3046';
const deployId = '1';

const restletUrl = `https://${accountId}.restlets.api.netsuite.com/app/site/hosting/restlet.nl?script=${scriptId}&deploy=${deployId}`;

function generateOAuthHeader(method, urlStr) {
  const parsedUrl = url.parse(urlStr, true);
  const baseUrl = `${parsedUrl.protocol}//${parsedUrl.host}${parsedUrl.pathname}`;
  const queryParams = parsedUrl.query;

  const oauthParams = {
    oauth_consumer_key: consumerKey,
    oauth_token: tokenId,
    oauth_signature_method: 'HMAC-SHA256',
    oauth_timestamp: Math.floor(Date.now() / 1000).toString(),
    oauth_nonce: crypto.randomBytes(16).toString('base64').replace(/[^a-zA-Z0-9]/g, '').slice(0, 32),
    oauth_version: '1.0',
  };

  const allParams = { ...oauthParams, ...queryParams };
  const sortedParams = Object.keys(allParams).sort().reduce((acc, key) => {
    acc[key] = allParams[key];
    return acc;
  }, {});

  const baseString = [
    method.toUpperCase(),
    encodeURIComponent(baseUrl),
    encodeURIComponent(querystring.stringify(sortedParams)),
  ].join('&');

  const signingKey = `${encodeURIComponent(consumerSecret)}&${encodeURIComponent(tokenSecret)}`;
  const signature = crypto.createHmac('sha256', signingKey).update(baseString).digest('base64');

  oauthParams.oauth_signature = signature;

  return `OAuth realm="${accountId}",${Object.keys(oauthParams).sort().map(
    (key) => `${key}="${encodeURIComponent(oauthParams[key])}"`
  ).join(',')}`;
}

const upload = multer();
const apiRoute = nextConnect();

apiRoute.use(upload.single('fileUpload'));

apiRoute.post(async (req, res) => {
  const body = {
    fileName: req.file.originalname,
    fileContent: req.file.buffer.toString('base64'),
    ...req.body,
  };

  delete body.script;
  delete body.deploy;

  try {
    const headers = {
      Authorization: generateOAuthHeader('POST', restletUrl),
      'Content-Type': 'application/json',
    };

    const response = await axios.post(restletUrl, body, { headers });
    res.status(response.status).json(response.data);
  } catch (err) {
    res.status(err.response?.status || 500).json({ error: err.message });
  }
});

export default apiRoute;
