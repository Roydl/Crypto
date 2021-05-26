namespace Roydl.Crypto.Checksum
{
    using System.IO;
    using System.Security.Cryptography;
    using Internal;

    /// <summary>Provides functionality to compute SHA-256 hashes.</summary>
    public sealed class Sha256 : ChecksumAlgorithm<Sha256>
    {
        private byte[] _secretKey;

        /// <summary>The secret key for <see cref="HMAC"/> encryption. The key can be any length. However, the recommended size is 64 bytes. If the key is more than 64 bytes long, it is hashed (using SHA-256) to derive a 64-byte key. If it is less than 64 bytes long, it is padded to 64 bytes.</summary>
        /// <remarks>Before overwriting an old key, see <see cref="DestroySecretKey()"/>.</remarks>
        public byte[] SecretKey
        {
            get => _secretKey;
            set => _secretKey = value;
        }

        /// <summary>Initializes a new instance of the <see cref="Sha256"/> class.</summary>
        public Sha256() : base(256) { }

        /// <summary>Initializes a new instance of the <see cref="Sha256"/> class and encrypts the specified stream.</summary>
        /// <inheritdoc cref="IChecksumAlgorithm.Encrypt(Stream)"/>
        public Sha256(Stream stream) : this() =>
            Encrypt(stream);

        /// <summary>Initializes a new instance of the <see cref="Sha256"/> class and encrypts the specified sequence of bytes.</summary>
        /// <inheritdoc cref="ChecksumAlgorithm(int, byte[])"/>
        public Sha256(byte[] bytes) : base(256, bytes) { }

        /// <summary>Initializes a new instance of the <see cref="Sha256"/> class and encrypts the specified text or file.</summary>
        /// <inheritdoc cref="ChecksumAlgorithm(int, string, bool)"/>
        public Sha256(string textOrFile, bool strIsFilePath) : this()
        {
            if (strIsFilePath)
            {
                EncryptFile(textOrFile);
                return;
            }
            Encrypt(textOrFile);
        }

        /// <summary>Initializes a new instance of the <see cref="Sha256"/> class and encrypts the specified text.</summary>
        /// <inheritdoc cref="ChecksumAlgorithm(int, string)"/>
        public Sha256(string text) : this(text, false) { }

        /// <inheritdoc/>
        public override void Encrypt(Stream stream) =>
            Encrypt(stream, (HashAlgorithm)(SecretKey == null ? SHA256.Create() : new HMACSHA256(SecretKey)));

        /// <inheritdoc cref="IChecksumAlgorithm.Encrypt(string)"/>
        public new void Encrypt(string text) =>
            Encrypt(text, (HashAlgorithm)(SecretKey == null ? SHA256.Create() : new HMACSHA256(SecretKey)));

        /// <summary>Removes the specified <see cref="SecretKey"/> from current process memory.</summary>
        /// <inheritdoc cref="Md5.DestroySecretKey()"/>
        public void DestroySecretKey() =>
            Helper.DestroyElement(ref _secretKey);
    }
}
