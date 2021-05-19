namespace Roydl.Crypto.Checksum
{
    using System.IO;
    using System.Security.Cryptography;

    /// <summary>
    ///     Provides functionality to compute SHA-512 hashes.
    /// </summary>
    public sealed class Sha512 : ChecksumAlgorithm<Sha512>
    {
        private byte[] _secretKey;

        /// <summary>
        ///     The secret key for <see cref="HMAC"/> encryption. The key can be any
        ///     length. However, the recommended size is 64 bytes. If the key is more than
        ///     64 bytes long, it is hashed (SHA-1) to derive a 64-byte key. If it is less
        ///     than 64 bytes long, it is padded to 64 bytes.
        ///     <para>
        ///         Before overwriting an old key, see <see cref="DestroySecretKey()"/>.
        ///     </para>
        /// </summary>
        public byte[] SecretKey
        {
            get => _secretKey;
            set => _secretKey = value;
        }

        /// <summary>
        ///     Initializes a new instance of the <see cref="Sha512"/> class.
        /// </summary>
        public Sha512() : base(512) { }

        /// <summary>
        ///     Initializes a new instance of the <see cref="Sha512"/> class and encrypts
        ///     the specified stream.
        /// </summary>
        /// <inheritdoc cref="Adler32(Stream)"/>
        public Sha512(Stream stream) : this() =>
            Encrypt(stream);

        /// <summary>
        ///     Initializes a new instance of the <see cref="Sha512"/> class and encrypts
        ///     the specified sequence of bytes.
        /// </summary>
        /// <inheritdoc cref="Adler32(byte[])"/>
        public Sha512(byte[] bytes) : this() =>
            Encrypt(bytes);

        /// <summary>
        ///     Initializes a new instance of the <see cref="Sha512"/> class and encrypts
        ///     the specified text or file.
        /// </summary>
        /// <inheritdoc cref="Adler32(string, bool)"/>
        public Sha512(string textOrFile, bool strIsFilePath) : this()
        {
            if (strIsFilePath)
            {
                EncryptFile(textOrFile);
                return;
            }
            Encrypt(textOrFile);
        }

        /// <summary>
        ///     Initializes a new instance of the <see cref="Sha512"/> class and encrypts
        ///     the specified text.
        /// </summary>
        /// <inheritdoc cref="Adler32(string)"/>
        public Sha512(string str) : this() =>
            Encrypt(str);

        /// <inheritdoc/>
        public override void Encrypt(Stream stream) =>
            Encrypt(stream, (HashAlgorithm)(SecretKey == null ? SHA512.Create() : new HMACSHA512(SecretKey)));

        /// <inheritdoc cref="IChecksumAlgorithm.Encrypt(string)"/>
        public new void Encrypt(string text) =>
            Encrypt(text, (HashAlgorithm)(SecretKey == null ? SHA512.Create() : new HMACSHA512(SecretKey)));

        /// <summary>
        ///     Removes the specified <see cref="SecretKey"/> from current process memory.
        ///     <para>
        ///         Note that the element cannot be removed if there are references outside
        ///         of this instance.
        ///     </para>
        /// </summary>
        public void DestroySecretKey() =>
            CryptoUtils.DestroyElement(ref _secretKey);
    }
}
