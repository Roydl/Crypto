namespace Roydl.Crypto.Checksum
{
    using System.IO;
    using System.Security.Cryptography;

    /// <summary>
    ///     Provides functionality to compute SHA-256 hashes.
    /// </summary>
    public sealed class Sha256 : ChecksumAlgorithm<Sha256>
    {
        /// <summary>
        ///     Initializes a new instance of the <see cref="Sha256"/> class.
        /// </summary>
        public Sha256() : base(256) { }

        /// <summary>
        ///     Initializes a new instance of the <see cref="Sha256"/> class and encrypts
        ///     the specified stream.
        /// </summary>
        /// <param name="stream">
        ///     The stream to encrypt.
        /// </param>
        public Sha256(Stream stream) : this() =>
            Encrypt(stream);

        /// <summary>
        ///     Initializes a new instance of the <see cref="Sha256"/> class and encrypts
        ///     the specified sequence of bytes.
        /// </summary>
        /// <param name="bytes">
        ///     The sequence of bytes to encrypt.
        /// </param>
        public Sha256(byte[] bytes) : this() =>
            Encrypt(bytes);

        /// <summary>
        ///     Initializes a new instance of the <see cref="Sha256"/> class and encrypts
        ///     the specified text or file.
        /// </summary>
        /// <param name="textOrFile">
        ///     The text or file to encrypt.
        /// </param>
        /// <param name="strIsFilePath">
        ///     <see langword="true"/> if the specified value is a file path; otherwise,
        ///     <see langword="false"/>.
        /// </param>
        public Sha256(string textOrFile, bool strIsFilePath) : this()
        {
            if (strIsFilePath)
            {
                EncryptFile(textOrFile);
                return;
            }
            Encrypt(textOrFile);
        }

        /// <summary>
        ///     Initializes a new instance of the <see cref="Sha256"/> class and encrypts
        ///     the specified text.
        /// </summary>
        /// <param name="str">
        ///     The text to encrypt.
        /// </param>
        public Sha256(string str) : this() =>
            Encrypt(str);

        /// <summary>
        ///     Encrypts the specified stream.
        /// </summary>
        /// <param name="stream">
        ///     The stream to encrypt.
        /// </param>
        public override void Encrypt(Stream stream) =>
            Encrypt(stream, new SHA256CryptoServiceProvider());

        /// <summary>
        ///     Encrypts the specified string.
        /// </summary>
        /// <param name="text">
        ///     The string to encrypt.
        /// </param>
        public new void Encrypt(string text)
        {
            var algo = default(SHA256);
            try
            {
                algo = SHA256.Create();
                Encrypt(text, algo);
            }
            finally
            {
                algo?.Dispose();
            }
        }
    }
}
