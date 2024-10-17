import crypto from 'crypto';

function hmacSHA256(key, message) {
  return crypto.createHmac('sha256', key).update(message).digest();
}

function getSignatureKey(secretKey, dateStamp, regionName, serviceName) {
  const kDate = hmacSHA256(`AWS4${secretKey}`, dateStamp);
  const kRegion = hmacSHA256(kDate, regionName);
  const kService = hmacSHA256(kRegion, serviceName);
  const kSigning = hmacSHA256(kService, 'aws4_request');
  return kSigning;
}

function createCanonicalRequest(method, canonicalUri, canonicalQueryString, canonicalHeaders, signedHeaders, payloadHash) {
  return [
      method,
      canonicalUri,
      canonicalQueryString,
      canonicalHeaders,
      signedHeaders,
      payloadHash
  ].join('\n');
}

function createStringToSign(algorithm, requestDate, credentialScope, canonicalRequest) {
  const hash = crypto.createHash('sha256').update(canonicalRequest).digest('hex');
  return [
      algorithm,
      requestDate,
      credentialScope,
      hash
  ].join('\n');
}

export function signRequest(method, uri, queryString, headers, payload, accessKey, secretKey, region, service, dateStamp, requestDate) {
  const algorithm = 'AWS4-HMAC-SHA256';
  const credentialScope = `${dateStamp}/${region}/${service}/aws4_request`;
  
  // Step 1: Criar a string canônica
  const signedHeaders = 'host;x-amz-content-sha256;x-amz-date';
  const canonicalRequest = createCanonicalRequest(method, uri, queryString, headers, signedHeaders, crypto.createHash('sha256').update(payload).digest('hex'));

  // Step 2: Criar a string para assinar
  const stringToSign = createStringToSign(algorithm, requestDate, credentialScope, canonicalRequest);

  // Step 3: Gerar a chave de assinatura
  const signingKey = getSignatureKey(secretKey, dateStamp, region, service);

  // Step 4: Assinar a string para assinar
  const signature = crypto.createHmac('sha256', signingKey).update(stringToSign).digest('hex');

  // Montar o cabeçalho de autorização
  const authorizationHeader = `${algorithm} Credential=${accessKey}/${credentialScope}, SignedHeaders=${signedHeaders}, Signature=${signature}`;

  return {
    'Authorization': authorizationHeader,
    'host': host,
    'x-amz-content-sha256': sha256Content,
    'x-amz-date': requestDate,
  };
}