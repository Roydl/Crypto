namespace Roydl.Crypto.Checksum
{
    using System.IO;
    using System.Security.Cryptography;

    /// <summary>
    ///     Provides functionality to compute MD5 hashes.
    /// </summary>
    public sealed class Md5 : ChecksumAlgorithm<Md5>
    {
        /// <summary>
        ///     Initializes a new instance of the <see cref="Md5"/> class.
        /// </summary>
        public Md5() : base(128) { }

        /// <summary>
        ///     Initializes a new instance of the <see cref="Md5"/> class and encrypts the
        ///     specified stream.
        /// </summary>
        /// <param name="stream">
        ///     The stream to encrypt.
        /// </param>
        public Md5(Stream stream) : this() =>
            Encrypt(stream);

        /// <summary>
        ///     Initializes a new instance of the <see cref="Md5"/> class and encrypts the
        ///     specified sequence of bytes.
        /// </summary>
        /// <param name="bytes">
        ///     The sequence of bytes to encrypt.
        /// </param>
        public Md5(byte[] bytes) : this() =>
            Encrypt(bytes);

        /// <summary>
        ///     Initializes a new instance of the <see cref="Md5"/> class and encrypts the
        ///     specified text or file.
        /// </summary>
        /// <param name="textOrFile">
        ///     The text or file to encrypt.
        /// </param>
        /// <param name="strIsFilePath">
        ///     <see langword="true"/> if the specified value is a file path; otherwise,
        ///     <see langword="false"/>.
        /// </param>
        public Md5(string textOrFile, bool strIsFilePath) : this()
        {
            if (strIsFilePath)
            {
                EncryptFile(textOrFile);
                return;
            }
            Encrypt(textOrFile);
        }

        /// <summary>
        ///     Initializes a new instance of the <see cref="Md5"/> class and encrypts the
        ///     specified text.
        /// </summary>
        /// <param name="str">
        ///     The text to encrypt.
        /// </param>
        public Md5(string str) : this() =>
            Encrypt(str);

        /// <summary>
        ///     Encrypts the specified stream.
        /// </summary>
        /// <param name="stream">
        ///     The stream to encrypt.
        /// </param>
        public override void Encrypt(Stream stream) =>
            Encrypt(stream, new MD5CryptoServiceProvider());

        /// <summary>
        ///     Encrypts the specified string.
        /// </summary>
        /// <param name="text">
        ///     The string to encrypt.
        /// </param>
        public new void Encrypt(string text)
        {
            var algo = default(MD5);
            try
            {
                algo = MD5.Create();
                Encrypt(text, algo);
            }
            finally
            {
                algo?.Dispose();
            }
        }
    }
}
