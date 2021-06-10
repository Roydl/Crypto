namespace Roydl.Crypto.Checksum
{
    using System.IO;
    using System.Numerics;
    using System.Security.Cryptography;
    using Internal;

    /// <summary>Provides functionality to compute MD5 hashes.</summary>
    public sealed class Md5 : ChecksumAlgorithm<Md5, BigInteger>
    {
        private byte[] _secretKey;

        /// <summary>The secret key for <see cref="HMAC"/> encryption. The key can be any length. However, the recommended size is 64 bytes. If the key is more than 64 bytes long, it is hashed (using SHA-1) to derive a 64-byte key. If it is less than 64 bytes long, it is padded to 64 bytes.</summary>
        /// <remarks>Before overwriting an old key, see <see cref="DestroySecretKey()"/>.</remarks>
        public byte[] SecretKey
        {
            get => _secretKey;
            set => _secretKey = value;
        }

        /// <summary>Initializes a new instance of the <see cref="Md5"/> class.</summary>
        public Md5() : base(128) { }

        /// <summary>Initializes a new instance of the <see cref="Md5"/> class.</summary>
        /// <param name="secretKey">The secret key for <see cref="HMAC"/> encryption.</param>
        /// <remarks>For more information, see <see cref="SecretKey">here</see>.</remarks>
        /// <returns>A newly created <see cref="Md5"/> instance.</returns>
        public static Md5 Create(byte[] secretKey = null) =>
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
        /// <remarks>Additional information:
        ///     <list type="bullet">
        ///         <item><description>The data cannot be removed if referenced outside of this instance.</description></item>
        ///         <item><description>Depending on the system, removing the data can take several seconds.</description></item>
        ///     </list>
        /// </remarks>
        public void DestroySecretKey() =>
            Helper.DestroyElement(ref _secretKey);

        private HashAlgorithm CreateHashAlgorithm() =>
            SecretKey == null ? MD5.Create() : new HMACMD5(SecretKey);
    }
}
