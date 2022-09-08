/* 
Lightweight HTTP 1.0 client for Node.js

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED,
INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A
PARTICULAR PURPOSE, TITLE AND NON-INFRINGEMENT. IN NO EVENT SHALL THE COPYRIGHT
HOLDERS OR ANYONE DISTRIBUTING THE SOFTWARE BE LIABLE FOR ANY DAMAGES OR OTHER
LIABILITY, WHETHER IN CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

import { Socket } from 'net';

const splitWithTail = (str, delim, count) => {
  const parts = str.split(delim);
  const tail = parts.slice(count).join(delim);
  const result = parts.slice(0, count);
  result.push(tail);
  return result;
};

const parseResponse = (response) => {
  const headers = {};
  const [head, body] = response.split('\r\n\r\n');
  const [statusLine, ...headerLines] = head.split('\r\n');
  const [httpVersion, statusCodeString, statusMessage] = splitWithTail(statusLine, ' ', 2);
  const statusCode = parseInt(statusCodeString, 10);
  headerLines.forEach((line) => {
    const [key, value] = line.split(': ');
    headers[key] = value;
  });
  return {
    httpVersion,
    statusCode,
    statusMessage,
    headers,
    body
  };
};

export const request = async (url, options) => {
  const parsedUrl = new URL(url);

  const client = new Socket();
  client.setEncoding('utf8');
  client.connect(parsedUrl.port || 80, parsedUrl.hostname, () => {
    let request = '';
    request += `${options.method} ${parsedUrl.pathname + parsedUrl.search} HTTP/1.0\r\n`;
    request += `Host: ${parsedUrl.host}\r\n`;
    for (const header in options.headers) {
      if (header.includes('\r\n') || options.headers[header].includes('\r\n')) {
        continue;
      }
      request += `${header}: ${options.headers[header]}\r\n`;
    }
    if (options.body) {
      request += `Content-Type: text/plain\r\n`;
      request += `Content-Length: ${options.body.length}\r\n`;
    } else {
      request += `Content-Length: 0\r\n`;
    }
    request += `Connection: close\r\n`;
    request += `\r\n`;
    if (options.body) {
      request += options.body;
    }

    client.write(request);
  });

  let response = '';

  client.on('data', (data) => {
    response += data;
  });

  return new Promise((resolve, reject) => {
    client.on('error', (e) => {
      reject(e);
    });

    client.on('close', function () {
      resolve(parseResponse(response));
    });
  });
};
