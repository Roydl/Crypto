namespace Roydl.Crypto.Checksum
{
    using System.IO;
    using System.Security.Cryptography;

    /// <summary>
    ///     Provides functionality to compute SHA-384 hashes.
    /// </summary>
    public sealed class Sha384 : ChecksumAlgorithm<Sha384>
    {
        private byte[] _secretKey;

        /// <summary>
        ///     The secret key for <see cref="HMAC"/> encryption. The key can be any
        ///     length. However, the recommended size is 128 bytes. If the key is more than
        ///     128 bytes long, it is hashed (using SHA-384) to derive a 128-byte key. If
        ///     it is less than 128 bytes long, it is padded to 128 bytes.
        /// </summary>
        /// <remarks>
        ///     Before overwriting an old key, see <see cref="DestroySecretKey()"/>.
        /// </remarks>
        public byte[] SecretKey
        {
            get => _secretKey;
            set => _secretKey = value;
        }

        /// <summary>
        ///     Initializes a new instance of the <see cref="Sha384"/> class.
        /// </summary>
        public Sha384() : base(384) { }

        /// <summary>
        ///     Initializes a new instance of the <see cref="Sha384"/> class and encrypts
        ///     the specified stream.
        /// </summary>
        /// <inheritdoc cref="IChecksumAlgorithm.Encrypt(Stream)"/>
        public Sha384(Stream stream) : this() =>
            Encrypt(stream);

        /// <summary>
        ///     Initializes a new instance of the <see cref="Sha384"/> class and encrypts
        ///     the specified sequence of bytes.
        /// </summary>
        /// <inheritdoc cref="IChecksumAlgorithm.Encrypt(byte[])"/>
        public Sha384(byte[] bytes) : this() =>
            Encrypt(bytes);

        /// <summary>
        ///     Initializes a new instance of the <see cref="Sha384"/> class and encrypts
        ///     the specified text or file.
        /// </summary>
        /// <inheritdoc cref="Adler32(string, bool)"/>
        public Sha384(string textOrFile, bool strIsFilePath) : this()
        {
            if (strIsFilePath)
            {
                EncryptFile(textOrFile);
                return;
            }
            Encrypt(textOrFile);
        }

        /// <summary>
        ///     Initializes a new instance of the <see cref="Sha384"/> class and encrypts
        ///     the specified text.
        /// </summary>
        /// <inheritdoc cref="IChecksumAlgorithm.Encrypt(string)"/>
        public Sha384(string text) : this() =>
            Encrypt(text);

        /// <inheritdoc/>
        public override void Encrypt(Stream stream) =>
            Encrypt(stream, (HashAlgorithm)(SecretKey == null ? SHA384.Create() : new HMACSHA384(SecretKey)));

        /// <inheritdoc cref="IChecksumAlgorithm.Encrypt(string)"/>
        public new void Encrypt(string text) =>
            Encrypt(text, (HashAlgorithm)(SecretKey == null ? SHA384.Create() : new HMACSHA384(SecretKey)));

        /// <summary>
        ///     Removes the specified <see cref="SecretKey"/> from current process memory.
        /// </summary>
        /// <inheritdoc cref="Md5.DestroySecretKey()"/>
        public void DestroySecretKey() =>
            CryptoUtils.DestroyElement(ref _secretKey);
    }
}
