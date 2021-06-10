namespace Roydl.Crypto.Checksum
{
    using System.IO;
    using System.Numerics;
    using System.Security.Cryptography;
    using Internal;

    /// <summary>Provides functionality to compute SHA-512 hashes.</summary>
    public sealed class Sha512 : ChecksumAlgorithm<Sha512, BigInteger>
    {
        private byte[] _secretKey;

        /// <summary>The secret key for <see cref="HMAC"/> encryption. The key can be any length. However, the recommended size is 128 bytes. If the key is more than 128 bytes long, it is hashed (using SHA-512) to derive a 128-byte key. If it is less than 128 bytes long, it is padded to 128 bytes.</summary>
        /// <remarks>Before overwriting an old key, see <see cref="DestroySecretKey()"/>.</remarks>
        public byte[] SecretKey
        {
            get => _secretKey;
            set => _secretKey = value;
        }

        /// <summary>Initializes a new instance of the <see cref="Sha512"/> class.</summary>
        public Sha512() : base(512) { }

        /// <summary>Initializes a new instance of the <see cref="Sha512"/> class.</summary>
        /// <param name="secretKey">The secret key for <see cref="HMAC"/> encryption.</param>
        /// <remarks>For more information, see <see cref="SecretKey">here</see>.</remarks>
        /// <returns>A newly created <see cref="Sha512"/> instance.</returns>
        public static Sha512 Create(byte[] secretKey = null) =>
            new() { SecretKey = secretKey };

        /// <inheritdoc/>
        public override void Encrypt(Stream stream)
        {
            Reset();
            Encrypt(stream, CreateHashAlgorithm());
        }

        /// <inheritdoc/>
        public override void Encrypt(byte[] bytes)
        {
            Reset();
            Encrypt(bytes, CreateHashAlgorithm());
        }

        /// <inheritdoc cref="IChecksumAlgorithm.Encrypt(string)"/>
        public new void Encrypt(string text)
        {
            Reset();
            Encrypt(text, CreateHashAlgorithm());
        }

        /// <summary>Removes the specified <see cref="SecretKey"/> from current process memory.</summary>
        /// <inheritdoc cref="Md5.DestroySecretKey()"/>
        public void DestroySecretKey() =>
            Helper.DestroyElement(ref _secretKey);

        private HashAlgorithm CreateHashAlgorithm() =>
            SecretKey == null ? SHA512.Create() : new HMACSHA512(SecretKey);
    }
}
