namespace Roydl.Crypto.Checksum
{
    using System.IO;
    using System.Security.Cryptography;
    using Internal;

    /// <summary>Provides functionality to compute SHA-512 hashes.</summary>
    public sealed class Sha512 : ChecksumAlgorithm<Sha512>
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

        /// <summary>Initializes a new instance of the <see cref="Sha512"/> class and encrypts the specified stream.</summary>
        /// <inheritdoc cref="IChecksumAlgorithm.Encrypt(Stream)"/>
        public Sha512(Stream stream) : this() =>
            Encrypt(stream);

        /// <summary>Initializes a new instance of the <see cref="Sha512"/> class and encrypts the specified sequence of bytes.</summary>
        /// <inheritdoc cref="ChecksumAlgorithm(int, byte[])"/>
        public Sha512(byte[] bytes) : base(512, bytes) { }

        /// <summary>Initializes a new instance of the <see cref="Sha512"/> class and encrypts the specified text or file.</summary>
        /// <inheritdoc cref="ChecksumAlgorithm(int, string, bool)"/>
        public Sha512(string textOrFile, bool strIsFilePath) : this()
        {
            if (strIsFilePath)
            {
                EncryptFile(textOrFile);
                return;
            }
            Encrypt(textOrFile);
        }

        /// <summary>Initializes a new instance of the <see cref="Sha512"/> class and encrypts the specified text.</summary>
        /// <inheritdoc cref="ChecksumAlgorithm(int, string)"/>
        public Sha512(string text) : this(text, false) { }

        /// <summary>Initializes a new instance of the <see cref="Sha512"/> class and encrypts the specified file.</summary>
        /// <inheritdoc cref="ChecksumAlgorithm(int, FileInfo)"/>
        public Sha512(FileInfo fileInfo) : base(512, fileInfo) { }

        /// <inheritdoc/>
        public override void Encrypt(Stream stream) =>
            Encrypt(stream, (HashAlgorithm)(SecretKey == null ? SHA512.Create() : new HMACSHA512(SecretKey)));

        /// <inheritdoc cref="IChecksumAlgorithm.Encrypt(string)"/>
        public new void Encrypt(string text) =>
            Encrypt(text, (HashAlgorithm)(SecretKey == null ? SHA512.Create() : new HMACSHA512(SecretKey)));

        /// <summary>Removes the specified <see cref="SecretKey"/> from current process memory.</summary>
        /// <inheritdoc cref="Md5.DestroySecretKey()"/>
        public void DestroySecretKey() =>
            Helper.DestroyElement(ref _secretKey);
    }
}
