import express from 'express';
import crypto from 'crypto';
import axios from 'axios';
import cors from 'cors';
import querystring from 'querystring';
import url from 'url';
import multer from 'multer';

const app = express();
const port = 3000;

const consumerKey = '2ff01625ff243c109e765d787c9ac0ca9c509d71302bc9888b930c4047b3ff02';
const consumerSecret = '06f6c64fb90b12cca30c7bc3fb71fdca978fa31cb3e135329610a9a2f4ac00e8';
const tokenId = 'c355e73e71fdb0c94b88ca91ec878b00c3b0ddee3837c4dfb6b32e9b90049dae';
const tokenSecret = '5af9e608cb52fc0a8d77d43cfaa0cdad5fa0aa3b87138813054265a84b596503';
const accountId = '3617444';
const scriptId = '3046';
const deployId = '1';

app.use(cors());
// Configure multer for file uploads
const upload = multer();
app.use(express.json());

// NetSuite RESTlet URL
const restletUrl = `https://${accountId}.restlets.api.netsuite.com/app/site/hosting/restlet.nl?script=${scriptId}&deploy=${deployId}`;

// OAuth 1.0a Signature Generator (mimicking Postman)
function generateOAuthHeader(method, urlStr, consumerKey, consumerSecret, tokenId, tokenSecret, accountId) {
  // Parse URL to extract query parameters
  const parsedUrl = url.parse(urlStr, true);
  const baseUrl = `${parsedUrl.protocol}//${parsedUrl.host}${parsedUrl.pathname}`;
  const queryParams = parsedUrl.query;

  // OAuth parameters
  const oauthParams = {
    oauth_consumer_key: consumerKey,
    oauth_token: tokenId,
    oauth_signature_method: 'HMAC-SHA256',
    oauth_timestamp: Math.floor(Date.now() / 1000).toString(),
    oauth_nonce: crypto.randomBytes(16).toString('base64').replace(/[^a-zA-Z0-9]/g, '').slice(0, 32),
    oauth_version: '1.0',
  };

  // Combine OAuth and query parameters (exclude body)
  const allParams = { ...oauthParams, ...queryParams };

  // Sort parameters alphabetically
  const sortedParams = Object.keys(allParams)
    .sort()
    .reduce((acc, key) => {
      acc[key] = allParams[key];
      return acc;
    }, {});

  // Create the base string
  const baseString = [
    method.toUpperCase(),
    encodeURIComponent(baseUrl),
    encodeURIComponent(querystring.stringify(sortedParams)),
  ].join('&');

  // Generate the signing key
  const signingKey = `${encodeURIComponent(consumerSecret)}&${encodeURIComponent(tokenSecret)}`;

  // Log for debugging
  console.log('OAuth Base String:', baseString);
  console.log('Signing Key:', signingKey);

  // Generate the signature
  const signature = crypto
    .createHmac('sha256', signingKey)
    .update(baseString)
    .digest('base64');

  // Add signature to OAuth parameters
  oauthParams.oauth_signature = signature;

  // Create Authorization header to match Postman's format
  const authHeader = `OAuth realm="${accountId}",${Object.keys(oauthParams)
    .sort()
    .map((key) => `${key}="${encodeURIComponent(oauthParams[key])}"`)
    .join(',')}`;

  return authHeader;
}

app.post('/submit', upload.single('fileUpload'), async (req, res) => {
  const method = 'POST';
  const body = {
    fileName: req.file.originalname,
    fileContent: req.file.buffer.toString('base64'), // Convert file to Base64
    ...req.body, // Include other form fields
};

  // Remove username/password/script/deploy from body (not needed for TBA)
  
  delete body.script;
  delete body.deploy;

  console.log('Request URL:', restletUrl);
  console.log('Request Body:', body);

  try {
    // Generate OAuth header
    const authHeader = generateOAuthHeader(
      method,
      restletUrl,
      consumerKey,
      consumerSecret,
      tokenId,
      tokenSecret,
      accountId
    );

    const headers = {
      Authorization: authHeader,
      'Content-Type': 'application/json',
    };

    console.log('Request Headers:', headers);

    // Make the request with axios
    const netsuiteRes = await axios({
      method: method,
      url: restletUrl,
      headers: headers,
      data: body,
    });

    console.log('Response Status:', netsuiteRes.status);
    console.log('Response Headers:', netsuiteRes.headers);
    console.log('Response Body:', netsuiteRes.data);

    res.status(netsuiteRes.status).json(netsuiteRes.data);
  } catch (err) {
    console.error('Error:', err.message);
    if (err.response) {
      console.log('Response Status:', err.response.status);
      console.log('Response Headers:', err.response.headers);
      console.log('Response Body:', err.response.data);
      res.status(err.response.status).json(err.response.data);
    } else {
      res.status(500).json({ error: err.message });
    }
  }
});

app.listen(port, () => {
  console.log(`✅ Server running at http://localhost:${port}`);
});