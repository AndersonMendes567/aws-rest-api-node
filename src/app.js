import fs from 'fs';
import 'dotenv/config';
import { signRequest } from './getSignedHeaders';

const method = 'GET';
const service = 's3';
const region = 'sa-east-1';
const host = 'mybucket4852.s3.sa-east-1.amazonaws.com';
const uri = '/pasta-1/coca.jpeg';
const queryString = '';
const payload = '';  // A solicitação GET geralmente não tem corpo
const accessKey = process.env.AWS_ACCESS_KEY;
const secretKey = process.env.AWS_SECRET_KEY;
const date = new Date();
const dateStamp = date.toISOString().slice(0, 10).replace(/-/g, '');
const requestDate = date.toISOString().replace(/[:\-]|\.\d{3}/g, '') + 'Z';
const sha256Content = crypto.createHash('sha256').update('').digest('hex')

const headers = `host:${host}\n` + `x-amz-content-sha256:${sha256Content}\n` + `x-amz-date:${requestDate}\n`;

const signedHeaders = signRequest(method, uri, queryString, headers, payload, accessKey, secretKey, region, service, dateStamp, requestDate);

const requestURL = `https://${host}${uri}`

console.log(accessKey, secretKey)

fetch(requestURL, {
  headers: signedHeaders
})
  .then(res=> res.arrayBuffer())
  .then(buffer=> {
    console.log(buffer)
    fs.writeFileSync('imagem.jpeg', Buffer.from(buffer))
  })