namespace Roydl.Crypto.Checksum
{
    using System;
    using System.IO;
    using Internal;

    /// <summary>Provides functionality to compute Adler-32 hashes.</summary>
    public sealed class Adler32 : ChecksumAlgorithm<Adler32>
    {
        /// <summary>Initializes a new instance of the <see cref="Adler32"/> class.</summary>
        public Adler32() : base(32) { }

        /// <summary>Initializes a new instance of the <see cref="Adler32"/> class and encrypts the specified stream.</summary>
        /// <inheritdoc cref="IChecksumAlgorithm.Encrypt(Stream)"/>
        public Adler32(Stream stream) : this() =>
            Encrypt(stream);

        /// <summary>Initializes a new instance of the <see cref="Adler32"/> class and encrypts the specified sequence of bytes.</summary>
        /// <inheritdoc cref="ChecksumAlgorithm(int, byte[])"/>
        public Adler32(byte[] bytes) : base(32, bytes) { }

        /// <summary>Initializes a new instance of the <see cref="Adler32"/> class and encrypts the specified text or file.</summary>
        /// <inheritdoc cref="ChecksumAlgorithm(int, string, bool)"/>
        public Adler32(string textOrFile, bool strIsFilePath) : base(32, textOrFile, strIsFilePath) { }

        /// <summary>Initializes a new instance of the <see cref="Adler32"/> class and encrypts the specified text.</summary>
        /// <inheritdoc cref="ChecksumAlgorithm(int, string)"/>
        public Adler32(string text) : base(32, text) { }

        /// <inheritdoc cref="ChecksumAlgorithm.Encrypt(Stream)"/>
        public override void Encrypt(Stream stream)
        {
            if (stream == null)
                throw new ArgumentNullException(nameof(stream));
            var ba = new byte[Helper.GetBufferSize(stream)].AsSpan();
            var uia = new[] { 1u, 0u }.AsSpan();
            int len;
            while ((len = stream.Read(ba)) > 0)
            {
                for (var i = 0; i < len; i++)
                {
                    uia[0] = (uia[0] + ba[i]) % 0xfff1;
                    uia[1] = (uia[1] + uia[0]) % 0xfff1;
                }
            }
            var num = ((uia[1] << 16) | uia[0]) & uint.MaxValue;
            HashNumber = num;
            RawHash = CryptoUtils.GetByteArray(num, RawHashSize);
        }
    }
}
