namespace Roydl.Crypto.Checksum
{
    using System;
    using System.IO;

    /// <summary>
    ///     Provides functionality to compute Adler-32 hashes.
    /// </summary>
    public sealed class Adler32 : ChecksumAlgorithm<Adler32>
    {
        /// <summary>
        ///     Initializes a new instance of the <see cref="Adler32"/> class.
        /// </summary>
        public Adler32() : base(32) { }

        /// <summary>
        ///     Initializes a new instance of the <see cref="Adler32"/> class and encrypts
        ///     the specified stream.
        /// </summary>
        /// <param name="stream">
        ///     The stream to encrypt.
        /// </param>
        public Adler32(Stream stream) : this() =>
            Encrypt(stream);

        /// <summary>
        ///     Initializes a new instance of the <see cref="Adler32"/> class and encrypts
        ///     the specified sequence of bytes.
        /// </summary>
        /// <param name="bytes">
        ///     The sequence of bytes to encrypt.
        /// </param>
        public Adler32(byte[] bytes) : this() =>
            Encrypt(bytes);

        /// <summary>
        ///     Initializes a new instance of the <see cref="Adler32"/> class and encrypts
        ///     the specified text or file.
        /// </summary>
        /// <param name="textOrFile">
        ///     The text or file to encrypt.
        /// </param>
        /// <param name="strIsFilePath">
        ///     <see langword="true"/> if the specified value is a file path; otherwise,
        ///     <see langword="false"/>.
        /// </param>
        public Adler32(string textOrFile, bool strIsFilePath) : this()
        {
            if (strIsFilePath)
            {
                EncryptFile(textOrFile);
                return;
            }
            Encrypt(textOrFile);
        }

        /// <summary>
        ///     Initializes a new instance of the <see cref="Adler32"/> class and encrypts
        ///     the specified text.
        /// </summary>
        /// <param name="str">
        ///     The text to encrypt.
        /// </param>
        public Adler32(string str) : this() =>
            Encrypt(str);

        /// <summary>
        ///     Encrypts the specified stream.
        /// </summary>
        /// <param name="stream">
        ///     The stream to encrypt.
        /// </param>
        /// <exception cref="ArgumentNullException">
        ///     stream is null.
        /// </exception>
        public override void Encrypt(Stream stream)
        {
            if (stream == null)
                throw new ArgumentNullException(nameof(stream));
            var ba = new byte[4096];
            var uia = new[]
            {
                1u,
                0u
            };
            int len;
            while ((len = stream.Read(ba, 0, ba.Length)) > 0)
            {
                for (var i = 0; i < len; i++)
                {
                    uia[0] = (uia[0] + ba[i]) % 0xfff1;
                    uia[1] = (uia[1] + uia[0]) % 0xfff1;
                }
            }
            var num = ((uia[1] << 16) | uia[0]) & uint.MaxValue;
            HashNumber = num;
            RawHash = CryptoUtils.GetByteArray(num, RawHashSize, true);
        }
    }
}
