namespace Roydl.Crypto.Checksum
{
    using System;
    using System.IO;

    /// <summary>
    ///     Provides functionality to compute CRC-16/AUG-CCITT hashes.
    /// </summary>
    public sealed class Crc16 : ChecksumAlgorithm<Crc16>
    {
        private static readonly CrcConfig<ushort> Current = new(16, 0x1021, 0x1d0f, false, false);

        /// <summary>
        ///     Initializes a new instance of the <see cref="Crc16"/> class.
        /// </summary>
        public Crc16() : base(16) { }

        /// <summary>
        ///     Initializes a new instance of the <see cref="Crc16"/> class and encrypts
        ///     the specified stream.
        /// </summary>
        /// <inheritdoc cref="IChecksumAlgorithm.Encrypt(Stream)"/>
        public Crc16(Stream stream) : this() =>
            Encrypt(stream);

        /// <summary>
        ///     Initializes a new instance of the <see cref="Crc16"/> class and encrypts
        ///     the specified sequence of bytes.
        /// </summary>
        /// <inheritdoc cref="ChecksumAlgorithm(int, byte[])"/>
        public Crc16(byte[] bytes) : base(16, bytes) { }

        /// <summary>
        ///     Initializes a new instance of the <see cref="Crc16"/> class and encrypts
        ///     the specified text or file.
        /// </summary>
        /// <inheritdoc cref="ChecksumAlgorithm(int, string, bool)"/>
        public Crc16(string textOrFile, bool strIsFilePath) : base(16, textOrFile, strIsFilePath) { }

        /// <summary>
        ///     Initializes a new instance of the <see cref="Crc16"/> class and encrypts
        ///     the specified text.
        /// </summary>
        /// <inheritdoc cref="ChecksumAlgorithm(int, string)"/>
        public Crc16(string text) : base(16, text) { }

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
