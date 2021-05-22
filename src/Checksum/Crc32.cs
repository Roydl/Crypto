namespace Roydl.Crypto.Checksum
{
    using System;
    using System.IO;

    /// <summary>
    ///     Provides functionality to compute CRC-32/ISO-HDLC hashes.
    /// </summary>
    public sealed class Crc32 : ChecksumAlgorithm<Crc32>
    {
        private static readonly CrcConfig<uint> Current = new(32, 0xedb88320u, uint.MaxValue, true, true);

        /// <summary>
        ///     Initializes a new instance of the <see cref="Crc32"/> class.
        /// </summary>
        public Crc32() : base(32) { }

        /// <summary>
        ///     Initializes a new instance of the <see cref="Crc32"/> class and encrypts
        ///     the specified stream.
        /// </summary>
        /// <inheritdoc cref="IChecksumAlgorithm.Encrypt(Stream)"/>
        public Crc32(Stream stream) : this() =>
            Encrypt(stream);

        /// <summary>
        ///     Initializes a new instance of the <see cref="Crc32"/> class and encrypts
        ///     the specified sequence of bytes.
        /// </summary>
        /// <inheritdoc cref="ChecksumAlgorithm(int, byte[])"/>
        public Crc32(byte[] bytes) : base(32, bytes) { }

        /// <summary>
        ///     Initializes a new instance of the <see cref="Crc32"/> class and encrypts
        ///     the specified text or file.
        /// </summary>
        /// <inheritdoc cref="ChecksumAlgorithm(int, string, bool)"/>
        public Crc32(string textOrFile, bool strIsFilePath) : base(32, textOrFile, strIsFilePath) { }

        /// <summary>
        ///     Initializes a new instance of the <see cref="Crc32"/> class and encrypts
        ///     the specified text.
        /// </summary>
        /// <inheritdoc cref="ChecksumAlgorithm(int, string)"/>
        public Crc32(string text) : base(32, text) { }

        /// <inheritdoc/>
        public override void Encrypt(Stream stream)
        {
            if (stream == null)
                throw new ArgumentNullException(nameof(stream));
            Current.ComputeHash(stream, out var num);
            HashNumber = num;
            RawHash = CryptoUtils.GetByteArray(num, RawHashSize);
        }
    }
}
