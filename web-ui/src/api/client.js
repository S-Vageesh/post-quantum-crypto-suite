import axios from 'axios';

const client = axios.create({
  baseURL: 'http://localhost:3001/api',
  headers: {
    'Content-Type': 'application/json',
  },
});

export const kyberApi = {
  generateKeyPair: () => client.post('/kyber/keypair'),
  encapsulate: (publicKey) => client.post('/kyber/encapsulate', { public_key: publicKey }),
  decapsulate: (secretKey, ciphertext) => client.post('/kyber/decapsulate', { secret_key: secretKey, ciphertext: ciphertext }),
};

export default client;
