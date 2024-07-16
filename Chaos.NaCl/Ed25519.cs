using System;
using System.Security.Cryptography;
using Chaos.NaCl.Internal.Ed25519Ref10;

namespace Chaos.NaCl
{
    /// <summary>
    /// A class to generate ed25519 keys (public and private) as well
    /// as generate ed25519 signatures and verify said signatures
    /// </summary>
    public static class Ed25519
    {
        /// <summary>
        /// Public key size in bytes
        /// </summary>
        public static readonly int PublicKeySizeInBytes = 32;
        /// <summary>
        /// Ed25519 signature size in bytes
        /// </summary>
        public static readonly int SignatureSizeInBytes = 64;
        /// <summary>
        /// Expanded private key size (size used in signature creation operations) in bytes
        /// </summary>
        public static readonly int ExpandedPrivateKeySizeInBytes = 32 * 2;
        /// <summary>
        /// Actual size of private key in bytes
        /// </summary>
        public static readonly int PrivateKeySeedSizeInBytes = 32;
        /// <summary>
        /// Size of key in key exchange operations
        /// </summary>
        public static readonly int SharedKeySizeInBytes = 32;

        /// <summary>
        /// Generate a private key seed in a cryptographically secure way.
        /// This key should be stored as your user's private key.
        /// </summary>
        /// <returns>An array of 32 bytes for the user's private key.</returns>
        public static string GeneratePrivateKeySeed()
        {
            return Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));
        }

        /// <summary>
        /// Verify an ed25519 signature given a message to verify and a public key
        /// </summary>
        /// <param name="signature">Signature to verify</param>
        /// <param name="message">Original message</param>
        /// <param name="publicKey">Public key for signature verification</param>
        /// <returns>True if signature is valid, false otherwise</returns>
        /// <exception cref="ArgumentException">Throws if signature or public key sizes are invalid</exception>
        public static bool Verify(ArraySegment<byte> signature, ArraySegment<byte> message, ArraySegment<byte> publicKey)
        {
            if (signature.Count != SignatureSizeInBytes)
                throw new ArgumentException(string.Format("Signature size must be {0}", SignatureSizeInBytes), "signature.Count");
            if (publicKey.Count != PublicKeySizeInBytes)
                throw new ArgumentException(string.Format("Public key size must be {0}", PublicKeySizeInBytes), "publicKey.Count");
            return Ed25519Operations.crypto_sign_verify(signature.Array, signature.Offset, message.Array, message.Offset, message.Count, publicKey.Array, publicKey.Offset);
        }

        /// <summary>
        /// Verify an ed25519 signature given a message to verify and a public key
        /// </summary>
        /// <param name="signature">Signature to verify</param>
        /// <param name="message">Original message</param>
        /// <param name="publicKey">Public key for signature verification</param>
        /// <returns>True if signature is valid, false otherwise</returns>
        /// <exception cref="ArgumentException">Throws if signature or public key sizes are invalid</exception>
        public static bool Verify(byte[] signature, byte[] message, byte[] publicKey)
        {
            return Verify(signature, message, message.Length, publicKey);
        }

        /// <summary>
        /// Verify an ed25519 signature given a message to verify and a public key
        /// </summary>
        /// <param name="signature">Signature to verify</param>
        /// <param name="message">Original message</param>
        /// <param name="messageLength">Length of message in bytes 
        /// (in case the message byte array contains more data that the message; 
        /// start index of message is assumed to be 0)</param>
        /// <param name="publicKey">Public key for signature verification</param>
        /// <returns>True if signature is valid, false otherwise</returns>
        /// <exception cref="ArgumentNullException">Throws if signature, message, or public key arguments are null</exception>
        /// <exception cref="ArgumentException">Throws if signature or public key sizes are invalid</exception>
        public static bool Verify(byte[] signature, byte[] message, int messageLength, byte[] publicKey)
        {
            if (signature == null)
                throw new ArgumentNullException("signature");
            if (message == null)
                throw new ArgumentNullException("message");
            if (publicKey == null)
                throw new ArgumentNullException("publicKey");
            if (signature.Length != SignatureSizeInBytes)
                throw new ArgumentException(string.Format("Signature size must be {0}", SignatureSizeInBytes), "signature.Length");
            if (publicKey.Length != PublicKeySizeInBytes)
                throw new ArgumentException(string.Format("Public key size must be {0}", PublicKeySizeInBytes), "publicKey.Length");
            return Ed25519Operations.crypto_sign_verify(signature, 0, message, 0, messageLength, publicKey, 0);
        }

        /// <summary>
        /// Create an ed25519 signature for the given message based on the given expanded private key
        /// </summary>
        /// <param name="signature">Output byte ArraySegment for the signature</param>
        /// <param name="message">Message to generate a signature for</param>
        /// <param name="expandedPrivateKey">Expanded private key (expanded from original private key via <seealso cref="ExpandedPrivateKeyFromSeed(byte[])"/>)</param>
        /// <exception cref="ArgumentNullException">Throws if signature.Array, expandedPrivateKey.Array, or message.Array are null</exception>
        /// <exception cref="ArgumentException">Throws if signature array size is incorrect or if the expanded private key is the wrong length</exception>
        public static void Sign(ArraySegment<byte> signature, ArraySegment<byte> message, ArraySegment<byte> expandedPrivateKey)
        {
            if (signature.Array == null)
                throw new ArgumentNullException("signature.Array");
            if (signature.Count != SignatureSizeInBytes)
                throw new ArgumentException("signature.Count");
            if (expandedPrivateKey.Array == null)
                throw new ArgumentNullException("expandedPrivateKey.Array");
            if (expandedPrivateKey.Count != ExpandedPrivateKeySizeInBytes)
                throw new ArgumentException("expandedPrivateKey.Count");
            if (message.Array == null)
                throw new ArgumentNullException("message.Array");
            Ed25519Operations.crypto_sign2(signature.Array, signature.Offset, message.Array, message.Offset, message.Count, expandedPrivateKey.Array, expandedPrivateKey.Offset);
        }

        /// <summary>
        /// Create an ed25519 signature for the given message based on the given expanded private key
        /// </summary>
        /// <param name="message">Message to generate a signature for</param>
        /// <param name="expandedPrivateKey">Expanded private key (expanded from original private key via <seealso cref="ExpandedPrivateKeyFromSeed(byte[])"/>)</param>
        /// <exception cref="ArgumentNullException">Throws if signature.Array, expandedPrivateKey.Array, or message.Array are null</exception>
        /// <exception cref="ArgumentException">Throws if signature array size is incorrect or if the expanded private key is the wrong length</exception>
        /// <returns>Signature for the given message</returns>
        public static byte[] Sign(byte[] message, byte[] expandedPrivateKey)
        {
            var signature = new byte[SignatureSizeInBytes];
            Sign(new ArraySegment<byte>(signature), new ArraySegment<byte>(message), new ArraySegment<byte>(expandedPrivateKey));
            return signature;
        }

        /// <summary>
        /// Create an ed25519 signature for the given message based on the given expanded private key
        /// </summary>
        /// <param name="message">Message to generate a signature for</param>
        /// <param name="expandedPrivateKey">Expanded private key (expanded from original private key via <seealso cref="ExpandedPrivateKeyFromSeed(byte[])"/>)</param>
        /// <param name="messageLength">Length of message in message byte array (start index is assumed to be 0)</param>
        /// <exception cref="ArgumentNullException">Throws if signature.Array, expandedPrivateKey.Array, or message.Array are null</exception>
        /// <exception cref="ArgumentException">Throws if signature array size is incorrect or if the expanded private key is the wrong length</exception>
        /// <returns>Signature for the given message</returns>
        public static byte[] Sign(byte[] message, int messageLength, byte[] expandedPrivateKey)
        {
            var signature = new byte[SignatureSizeInBytes];
            Sign(new ArraySegment<byte>(signature), new ArraySegment<byte>(message, 0, messageLength), new ArraySegment<byte>(expandedPrivateKey));
            return signature;
        }

        /// <summary>
        /// Generate the public key for the given private key seed that was generated via
        /// <seealso cref="GeneratePrivateKeySeed()"/>
        /// </summary>
        /// <param name="privateKeySeed"></param>
        /// <returns></returns>
        public static byte[] PublicKeyFromSeed(byte[] privateKeySeed)
        {
            byte[] privateKey;
            byte[] publicKey;
            KeyPairFromSeed(out publicKey, out privateKey, privateKeySeed);
            CryptoBytes.Wipe(privateKey);
            return publicKey;
        }

        /// <summary>
        /// Expands a private key from the initial private key seed for use in 
        /// signature generation function such as <seealso cref="Sign(byte[], byte[])"/>.
        /// </summary>
        /// <param name="privateKeySeed">The private key initially generated by <seealso cref="GeneratePrivateKeySeed()"/></param>
        /// <returns>A byte array that represents the expanded private key for the given seed</returns>
        public static byte[] ExpandedPrivateKeyFromSeed(byte[] privateKeySeed)
        {
            byte[] privateKey;
            byte[] publicKey;
            KeyPairFromSeed(out publicKey, out privateKey, privateKeySeed);
            CryptoBytes.Wipe(publicKey);
            return privateKey;
        }

        /// <summary>
        /// Generate both public and expanded private keys for the given private key seed
        /// </summary>
        /// <param name="publicKey">Output byte array for public key</param>
        /// <param name="expandedPrivateKey">Output byte array for expanded private key</param>
        /// <param name="privateKeySeed">Private key seed generated via <seealso cref="GeneratePrivateKeySeed()"/></param>
        /// <exception cref="ArgumentNullException">Throws if privateKeySeed is null</exception>
        /// <exception cref="ArgumentException">Throws if private key length is the wrong length</exception>
        public static void KeyPairFromSeed(out byte[] publicKey, out byte[] expandedPrivateKey, byte[] privateKeySeed)
        {
            if (privateKeySeed == null)
                throw new ArgumentNullException("privateKeySeed");
            if (privateKeySeed.Length != PrivateKeySeedSizeInBytes)
                throw new ArgumentException("privateKeySeed");
            var pk = new byte[PublicKeySizeInBytes];
            var sk = new byte[ExpandedPrivateKeySizeInBytes];
            Ed25519Operations.crypto_sign_keypair(pk, 0, sk, 0, privateKeySeed, 0);
            publicKey = pk;
            expandedPrivateKey = sk;
        }

        /// <summary>
        /// Generate both public and expanded private keys for the given private key seed
        /// </summary>
        /// <param name="publicKey">Output byte array for public key</param>
        /// <param name="expandedPrivateKey">Output byte array for expanded private key</param>
        /// <param name="privateKeySeed">Private key seed generated via <seealso cref="GeneratePrivateKeySeed()"/></param>
        /// <exception cref="ArgumentNullException">Throws if publicKey.Array, expandedPrivateKey.Array, or privateKeySeed.Array are null</exception>
        /// <exception cref="ArgumentException">Throws if public key array is the wrong size, if the expanded private key array is the wrong size, or if the private key is the wrong size</exception>
        public static void KeyPairFromSeed(ArraySegment<byte> publicKey, ArraySegment<byte> expandedPrivateKey, ArraySegment<byte> privateKeySeed)
        {
            if (publicKey.Array == null)
                throw new ArgumentNullException("publicKey.Array");
            if (expandedPrivateKey.Array == null)
                throw new ArgumentNullException("expandedPrivateKey.Array");
            if (privateKeySeed.Array == null)
                throw new ArgumentNullException("privateKeySeed.Array");
            if (publicKey.Count != PublicKeySizeInBytes)
                throw new ArgumentException("publicKey.Count");
            if (expandedPrivateKey.Count != ExpandedPrivateKeySizeInBytes)
                throw new ArgumentException("expandedPrivateKey.Count");
            if (privateKeySeed.Count != PrivateKeySeedSizeInBytes)
                throw new ArgumentException("privateKeySeed.Count");
            Ed25519Operations.crypto_sign_keypair(
                publicKey.Array, publicKey.Offset,
                expandedPrivateKey.Array, expandedPrivateKey.Offset,
                privateKeySeed.Array, privateKeySeed.Offset);
        }

        [Obsolete("Still needs testing; use this function with caution")]
        public static byte[] KeyExchange(byte[] publicKey, byte[] privateKey)
        {
            var sharedKey = new byte[SharedKeySizeInBytes];
            KeyExchange(new ArraySegment<byte>(sharedKey), new ArraySegment<byte>(publicKey), new ArraySegment<byte>(privateKey));
            return sharedKey;
        }

        [Obsolete("Still needs testing; use this function with caution")]
        public static void KeyExchange(ArraySegment<byte> sharedKey, ArraySegment<byte> publicKey, ArraySegment<byte> privateKey)
        {
            if (sharedKey.Array == null)
                throw new ArgumentNullException("sharedKey.Array");
            if (publicKey.Array == null)
                throw new ArgumentNullException("publicKey.Array");
            if (privateKey.Array == null)
                throw new ArgumentNullException("privateKey");
            if (sharedKey.Count != 32)
                throw new ArgumentException("sharedKey.Count != 32");
            if (publicKey.Count != 32)
                throw new ArgumentException("publicKey.Count != 32");
            if (privateKey.Count != 64)
                throw new ArgumentException("privateKey.Count != 64");

            FieldElement montgomeryX, edwardsY, edwardsZ, sharedMontgomeryX;
            FieldOperations.fe_frombytes(out edwardsY, publicKey.Array, publicKey.Offset);
            FieldOperations.fe_1(out edwardsZ);
            MontgomeryCurve25519.EdwardsToMontgomeryX(out montgomeryX, ref edwardsY, ref edwardsZ);
            byte[] h = Sha512.Hash(privateKey.Array, privateKey.Offset, 32);//ToDo: Remove alloc
            ScalarOperations.sc_clamp(h, 0);
            MontgomeryOperations.scalarmult(out sharedMontgomeryX, h, 0, ref montgomeryX);
            CryptoBytes.Wipe(h);
            FieldOperations.fe_tobytes(sharedKey.Array, sharedKey.Offset, ref sharedMontgomeryX);
            MontgomeryCurve25519.KeyExchangeOutputHashNaCl(sharedKey.Array, sharedKey.Offset);
        }
    }
}