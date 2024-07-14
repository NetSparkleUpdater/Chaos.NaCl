using System;
using System.Dynamic;
using System.IO;
using System.Security.Cryptography.X509Certificates;

namespace Chaos.NaCl
{
    /// <summary>
    /// API and constants modified from BouncyCastle on 2024-07-13 (MIT)
    /// </summary>
    public class Ed25519Signer : IDisposable
    {
        private const int CoordUints = 8;
        private const int PointBytes = CoordUints * 4;
        private const int ScalarUints = 8;
        private const int ScalarBytes = ScalarUints * 4;

        public static readonly int PrehashSize = 64;
        public static readonly int PublicKeySize = PointBytes;
        public static readonly int SecretKeySize = 32;
        public static readonly int SignatureSize = PointBytes + ScalarBytes;

        private readonly MemoryStream _buffer;
        private byte[] _publicKey;
        private byte[] _privateKey;

        public Ed25519Signer()
        {
            _buffer = new MemoryStream();
        }

        public virtual void Init(byte[] publicKey, byte[] privateKey)
        {
            if (publicKey != null && publicKey.Length != Ed25519.PublicKeySizeInBytes)
            {
                throw new Exception("Invalid public key length");
            }
            if (privateKey != null && privateKey.Length != Ed25519.ExpandedPrivateKeySizeInBytes)
            {
                throw new Exception("Invalid private key length");
            }
            _publicKey = publicKey;
            _privateKey = privateKey;
        }

        public void Dispose()
        {
            Reset();
        }

        public virtual void AddByteToBuffer(byte b)
        {
            _buffer.WriteByte(b);
        }

        public virtual void AddToBuffer(byte[] buf, int off, int len)
        {
            _buffer.Write(buf, off, len);
        }

        public virtual int GetMaxSignatureSize() => SignatureSize;

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