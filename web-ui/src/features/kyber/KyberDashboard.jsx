import React, { useState } from 'react';
import { kyberApi } from '../../api/client';
import { Shield, Key, Lock, Unlock, CheckCircle2, AlertCircle } from 'lucide-react';

const Card = ({ title, icon: Icon, children }) => (
  <div className="bg-white dark:bg-gray-800 rounded-xl shadow-lg p-6 mb-6">
    <div className="flex items-center mb-4">
      {Icon && <Icon className="w-6 h-6 mr-2 text-indigo-500" />}
      <h2 className="text-xl font-bold text-gray-800 dark:text-white">{title}</h2>
    </div>
    {children}
  </div>
);

const HexBox = ({ label, value, color = "indigo" }) => (
  <div className="mb-4">
    <label className="block text-sm font-medium text-gray-500 dark:text-gray-400 mb-1">{label}</label>
    <div className={`p-3 rounded bg-${color}-50 dark:bg-${color}-900/20 border border-${color}-100 dark:border-${color}-800 break-all font-mono text-xs`}>
      {value || "Not generated yet"}
    </div>
  </div>
);

export default function KyberDashboard() {
  const [bobKeys, setBobKeys] = useState(null);
  const [aliceData, setAliceData] = useState(null);
  const [bobDecaps, setBobDecaps] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  const handleGenerateKeys = async () => {
    setLoading(true);
    setError(null);
    try {
      const { data } = await kyberApi.generateKeyPair();
      setBobKeys(data);
      setAliceData(null);
      setBobDecaps(null);
    } catch (err) {
      setError("Failed to generate keypair");
    } finally {
      setLoading(false);
    }
  };

  const handleEncapsulate = async () => {
    if (!bobKeys) return;
    setLoading(true);
    setError(null);
    try {
      const { data } = await kyberApi.encapsulate(bobKeys.public_key);
      setAliceData(data);
      setBobDecaps(null);
    } catch (err) {
      setError("Encapsulation failed");
    } finally {
      setLoading(false);
    }
  };

  const handleDecapsulate = async () => {
    if (!aliceData || !bobKeys) return;
    setLoading(true);
    setError(null);
    try {
      const { data } = await kyberApi.decapsulate(bobKeys.secret_key, aliceData.ciphertext);
      setBobDecaps(data);
    } catch (err) {
      setError("Decapsulation failed");
    } finally {
      setLoading(false);
    }
  };

  const secretsMatch = aliceData && bobDecaps && aliceData.shared_secret === bobDecaps.shared_secret;

  return (
    <div className="max-w-4xl mx-auto p-8">
      <header className="text-center mb-12">
        <h1 className="text-4xl font-extrabold text-indigo-600 dark:text-indigo-400 mb-2">Kyber KEM Suite</h1>
        <p className="text-gray-600 dark:text-gray-400">Post-Quantum Cryptography Demonstration</p>
      </header>

      {error && (
        <div className="bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 text-red-600 p-4 rounded-lg mb-8 flex items-center">
          <AlertCircle className="w-5 h-5 mr-2" />
          {error}
        </div>
      )}

      {/* Step 1: Bob Generates Keys */}
      <Card title="Step 1: Bob's Key Generation" icon={Key}>
        <button
          onClick={handleGenerateKeys}
          disabled={loading}
          className="bg-indigo-600 hover:bg-indigo-700 text-white px-4 py-2 rounded-lg font-medium transition disabled:opacity-50 mb-4"
        >
          {loading ? "Generating..." : "Generate Kyber-768 Keypair"}
        </button>
        {bobKeys && (
          <>
            <HexBox label="Public Key (Bob sends this to Alice)" value={bobKeys.public_key} />
            <HexBox label="Secret Key (Bob keeps this private)" value={bobKeys.secret_key} color="red" />
          </>
        )}
      </Card>

      {/* Step 2: Alice Encapsulates */}
      <Card title="Step 2: Alice's Encapsulation" icon={Lock}>
        <p className="text-sm text-gray-500 mb-4">Alice uses Bob's public key to create a shared secret and a ciphertext.</p>
        <button
          onClick={handleEncapsulate}
          disabled={loading || !bobKeys}
          className="bg-green-600 hover:bg-green-700 text-white px-4 py-2 rounded-lg font-medium transition disabled:opacity-50 mb-4"
        >
          Encapsulate for Bob
        </button>
        {aliceData && (
          <>
            <HexBox label="Ciphertext (Alice sends this to Bob)" value={aliceData.ciphertext} color="green" />
            <HexBox label="Alice's Shared Secret" value={aliceData.shared_secret} color="blue" />
          </>
        )}
      </Card>

      {/* Step 3: Bob Decapsulates */}
      <Card title="Step 3: Bob's Decapsulation" icon={Unlock}>
        <p className="text-sm text-gray-500 mb-4">Bob uses his secret key to recover the shared secret from Alice's ciphertext.</p>
        <button
          onClick={handleDecapsulate}
          disabled={loading || !aliceData}
          className="bg-orange-600 hover:bg-orange-700 text-white px-4 py-2 rounded-lg font-medium transition disabled:opacity-50 mb-4"
        >
          Decapsulate Alice's Message
        </button>
        {bobDecaps && (
          <HexBox label="Bob's Recovered Shared Secret" value={bobDecaps.shared_secret} color="blue" />
        )}
      </Card>

      {/* Result Verification */}
      {secretsMatch && (
        <div className="bg-green-100 dark:bg-green-900/30 border-2 border-green-500 p-8 rounded-2xl text-center">
          <CheckCircle2 className="w-16 h-16 text-green-500 mx-auto mb-4" />
          <h3 className="text-2xl font-bold text-green-700 dark:text-green-400 mb-2">Secrets Match!</h3>
          <p className="text-green-600 dark:text-green-500">Alice and Bob have successfully established a secure post-quantum shared secret.</p>
        </div>
      )}
    </div>
  );
}
