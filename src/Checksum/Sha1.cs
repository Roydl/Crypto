namespace Roydl.Crypto.Checksum
{
    using System.IO;
    using System.Numerics;
    using System.Security.Cryptography;
    using Internal;

    /// <summary>Provides functionality to compute SHA-1 hashes.</summary>
    public sealed class Sha1 : ChecksumAlgorithm<Sha1, BigInteger>
    {
        private byte[] _secretKey;

        /// <summary>The secret key for <see cref="HMAC"/> encryption. The key can be any length. However, the recommended size is 64 bytes. If the key is more than 64 bytes long, it is hashed (using SHA-1) to derive a 64-byte key. If it is less than 64 bytes long, it is padded to 64 bytes.</summary>
        /// <remarks>Before overwriting an old key, see <see cref="DestroySecretKey()"/>.</remarks>
        public byte[] SecretKey
        {
            get => _secretKey;
            set => _secretKey = value;
        }

        /// <summary>Initializes a new instance of the <see cref="Sha1"/> class.</summary>
        public Sha1() : base(160) { }

        /// <summary>Initializes a new instance of the <see cref="Sha1"/> class and encrypts the specified stream.</summary>
        /// <inheritdoc cref="IChecksumAlgorithm.Encrypt(Stream)"/>
        public Sha1(Stream stream) : this() =>
            Encrypt(stream);

        /// <summary>Initializes a new instance of the <see cref="Sha1"/> class and encrypts the specified sequence of bytes.</summary>
        /// <inheritdoc cref="ChecksumAlgorithm(int, byte[])"/>
        public Sha1(byte[] bytes) : this() =>
            Encrypt(bytes);

        /// <summary>Initializes a new instance of the <see cref="Sha1"/> class and encrypts the specified text or file.</summary>
        /// <inheritdoc cref="ChecksumAlgorithm(int, string, bool)"/>
        public Sha1(string textOrFile, bool strIsFilePath) : this()
        {
            if (strIsFilePath)
            {
                EncryptFile(textOrFile);
                return;
            }
            Encrypt(textOrFile);
        }

        /// <summary>Initializes a new instance of the <see cref="Sha1"/> class and encrypts the specified text.</summary>
        /// <inheritdoc cref="ChecksumAlgorithm(int, string)"/>
        public Sha1(string text) : this(text, false) { }

        /// <summary>Initializes a new instance of the <see cref="Sha1"/> class and encrypts the specified file.</summary>
        /// <inheritdoc cref="ChecksumAlgorithm(int, FileInfo)"/>
        public Sha1(FileInfo fileInfo) : this() =>
            Encrypt(fileInfo);

        /// <summary>Initializes a new instance of the <see cref="Sha1"/> class.</summary>
        /// <param name="secretKey">The secret key for <see cref="HMAC"/> encryption.</param>
        /// <remarks>For more information, see <see cref="SecretKey">here</see>.</remarks>
        /// <returns>A newly created <see cref="Sha1"/> instance.</returns>
        public static Sha1 Create(byte[] secretKey = null) =>
            new() { SecretKey = secretKey };

        /// <inheritdoc/>
        public override void Encrypt(Stream stream)
        {
            Reset();
            Encrypt(stream, (HashAlgorithm)(SecretKey == null ? SHA1.Create() : new HMACSHA1(SecretKey)));
        }

        /// <inheritdoc cref="IChecksumAlgorithm.Encrypt(string)"/>
        public new void Encrypt(string text)
        {
            Reset();
            Encrypt(text, (HashAlgorithm)(SecretKey == null ? SHA1.Create() : new HMACSHA1(SecretKey)));
        }

        /// <summary>Removes the specified <see cref="SecretKey"/> from current process memory.</summary>
        /// <inheritdoc cref="Md5.DestroySecretKey()"/>
        public void DestroySecretKey() =>
            Helper.DestroyElement(ref _secretKey);
    }
}
