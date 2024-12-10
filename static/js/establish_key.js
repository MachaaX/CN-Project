// This script assumes:
// - The server endpoints `/get_public_key` and `/set_session_key` are accessible.
// - The server public key is an RSA public key in PEM format suitable for RSA-OAEP with SHA-256.
// - The client runs this code after user login.
// - You have a button or trigger to start the key exchange process.

async function fetchServerPublicKey() {
  const response = await fetch('/get_public_key');
  if (!response.ok) {
    throw new Error('Failed to retrieve public key from server.');
  }
  const pemKey = await response.text();
  return pemKey;
}

function pemToArrayBuffer(pem) {
  // Remove PEM header/footer and line breaks
  const pemContents = pem.replace(/-----BEGIN PUBLIC KEY-----/, '')
    .replace(/-----END PUBLIC KEY-----/, '')
    .replace(/\s+/g, '');
  const binaryString = atob(pemContents);
  const byteArray = new Uint8Array(binaryString.length);
  for (let i = 0; i < binaryString.length; i++) {
    byteArray[i] = binaryString.charCodeAt(i);
  }
  return byteArray.buffer;
}

async function importRSAPublicKey(pemKey) {
  const keyData = pemToArrayBuffer(pemKey);
  const publicKey = await window.crypto.subtle.importKey(
    'spki',
    keyData,
    {
      name: 'RSA-OAEP',
      hash: 'SHA-256'
    },
    true,
    ['encrypt']
  );
  return publicKey;
}

async function generateAESKey() {
  // Generate a 256-bit AES-GCM key (suitable for your session key)
  // Even if you use AES-CBC on the server, generating an AES-GCM key is still fine;
  // the raw key bytes are what matter. Just ensure 256 bits for AES-256.
  const key = await window.crypto.subtle.generateKey(
    {
      name: 'AES-GCM',
      length: 256
    },
    true,
    ['encrypt', 'decrypt']
  );
  // Export raw key bytes for encryption with RSA
  const rawKey = await window.crypto.subtle.exportKey('raw', key);
  return rawKey;
}

async function encryptSessionKeyWithRSA(publicKey, rawSessionKey) {
  const encryptedKey = await window.crypto.subtle.encrypt(
    {
      name: 'RSA-OAEP'
    },
    publicKey,
    rawSessionKey
  );
  return new Uint8Array(encryptedKey);
}

async function sendEncryptedSessionKey(encryptedSessionKey) {
  const response = await fetch('/set_session_key', {
    method: 'POST',
    body: encryptedSessionKey,
    headers: {
      'Content-Type': 'application/octet-stream'
    }
  });
  if (!response.ok) {
    const text = await response.text();
    throw new Error(`Failed to set session key: ${text}`);
  }
  const text = await response.text();
  return text;
}

// This is the main function to establish the key.
async function establishSessionKey() {
  try {
    // 1. Fetch server public key
    const pemKey = await fetchServerPublicKey();

    // 2. Import server public key
    const publicKey = await importRSAPublicKey(pemKey);

    // 3. Generate AES session key
    const rawSessionKey = await generateAESKey();

    // 4. Encrypt session key with server’s RSA public key
    const encryptedKey = await encryptSessionKeyWithRSA(publicKey, rawSessionKey);

    // 5. Send the encrypted session key to server
    const result = await sendEncryptedSessionKey(encryptedKey);
    console.log('Session key established:', result);

    // After this, the server knows the session key associated with the current user.
    // The user can now go to the patient profile page, submit data, etc., and the server
    // can encrypt/decrypt patient-specific data.
    
    // alert('Session key established successfully! You can now update your profile.');
  } catch (err) {
    console.error(err);
    alert(`Error establishing session key: ${err.message}`);
  }
}

// Optional: You could call establishSessionKey() on page load or attach it to a button click.
document.getElementById('establishKeyBtn').addEventListener('click', establishSessionKey);
