using System;
using System.Dynamic;
using System.IO;
using System.Security.Cryptography.X509Certificates;

namespace Chaos.NaCl
{
    /// <summary>
    /// Uses public key and EXPANDED private key (64 bytes) to
    /// create signatures and verify signatures for data.
    /// API modified from BouncyCastle on 2024-07-13 (MIT).
    /// </summary>
    public class Ed25519Signer : IDisposable
    {
        private readonly MemoryStream _buffer;
        private byte[] _publicKey;
        private byte[] _privateKey;

        /// <summary>
        /// A simple wrapper class around Ed25519 to assist in creating/validating ed25519 signatures
        /// </summary>
        public Ed25519Signer()
        {
            _buffer = new MemoryStream();
        }

        /// <summary>
        /// Initialize the Ed25519Signer with a public key and EXPANDED private key
        /// </summary>
        /// <param name="publicKey">32 byte public key</param>
        /// <param name="expandedPrivateKey">64 byte expanded private key</param>
        /// <exception cref="Exception">Throws exception if either key is the wrong length</exception>
        public virtual void Init(byte[] publicKey, byte[] expandedPrivateKey)
        {
            if (publicKey != null && publicKey.Length != Ed25519.PublicKeySizeInBytes)
            {
                throw new Exception("Invalid public key length");
            }
            if (expandedPrivateKey != null && expandedPrivateKey.Length != Ed25519.ExpandedPrivateKeySizeInBytes)
            {
                throw new Exception("Invalid private key length");
            }
            _publicKey = publicKey;
            _privateKey = expandedPrivateKey;
        }

        /// <summary>
        /// Initialize the Ed25519Signer with a private key seed rather than the expanded private key
        /// </summary>
        /// <param name="publicKey">32 byte public key</param>
        /// <param name="privateKey">32 byte private key (seed)</param>
        /// <exception cref="Exception">Throws exception if either key is the wrong length</exception>
        public virtual void InitWithNonExpandedPrivateKey(byte[] publicKey, byte[] privateKey)
        {
            if (publicKey != null && publicKey.Length != Ed25519.PublicKeySizeInBytes)
            {
                throw new Exception("Invalid public key length");
            }
            if (privateKey != null && privateKey.Length != Ed25519.PrivateKeySeedSizeInBytes)
            {
                throw new Exception("Invalid private key length");
            }
            _publicKey = publicKey;
            _privateKey = Ed25519.ExpandedPrivateKeyFromSeed(privateKey);
        }

        /// <summary>
        /// Dispose of any memory as needed; Calls Reset()
        /// </summary>
        public void Dispose()
        {
            Reset();
        }

        /// <summary>
        /// Add the given byte to the memory buffer
        /// </summary>
        /// <param name="b">The byte to append to the memory buffer</param>
        public virtual void AddByteToBuffer(byte b)
        {
            _buffer.WriteByte(b);
        }

        /// <summary>
        /// Add the given data in the given byte array to the memory buffer
        /// </summary>
        /// <param name="buf">Byte array with data in it</param>
        /// <param name="off">Offset to start of data</param>
        /// <param name="len">Length of data to add</param>
        public virtual void AddToBuffer(byte[] buf, int off, int len)
        {
            _buffer.Write(buf, off, len);
        }

        /// <summary>
        /// Generate a signature based on data in the buffer and the initialized private key
        /// </summary>
        /// <returns>An ed25519 signature for the current data</returns>
        /// <exception cref="Exception">Throws if the private key is not an expanded private key</exception>
        public virtual byte[] GenerateSignature()
        {
            if (_privateKey == null || _privateKey.Length != Ed25519.ExpandedPrivateKeySizeInBytes)
            {
                throw new Exception("Invalid private key length");
            }
            lock (_buffer)
            {
                var signature = Ed25519.Sign(_buffer.GetBuffer(), Convert.ToInt32(_buffer.Length), _privateKey);
                Reset();
                return signature;
            }
        }

        /// <summary>
        /// Verify the given signature against the data in the memory buffer and the public key
        /// </summary>
        /// <param name="signature">Signature to verify</param>
        /// <returns>True if the signature is valid; false otherwise</returns>
        /// <exception cref="Exception">Throws if the public key is not the appropriate length in bytes</exception>
        public virtual bool VerifySignature(byte[] signature)
        {
            if (_publicKey == null || _publicKey.Length != Ed25519.PublicKeySizeInBytes)
            {
                throw new Exception("Invalid public key length");
            }
            lock (_buffer)
            {
                var result = Ed25519.Verify(signature, _buffer.GetBuffer(), Convert.ToInt32(_buffer.Length), _publicKey);
                Reset();
                return result;
            }
        }

        /// <summary>
        /// Reset the in-memory data buffer by clearing it
        /// </summary>
        public virtual void Reset()
        {
            lock (_buffer)
            {
                int count = Convert.ToInt32(_buffer.Length);
                Array.Clear(_buffer.GetBuffer(), 0, count);
                _buffer.SetLength(0);
            }
        }
    }
}