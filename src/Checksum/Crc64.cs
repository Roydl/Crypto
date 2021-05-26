namespace Roydl.Crypto.Checksum
{
    using System;
    using System.IO;

    /// <summary>Provides functionality to compute CRC-64/ECMA hashes.</summary>
    public sealed class Crc64 : ChecksumAlgorithm<Crc64>
    {
        private static readonly CrcConfig<ulong> Current = new(64, 0x42f0e1eba9ea3693uL);

        /// <summary>Initializes a new instance of the <see cref="Crc64"/> class.</summary>
        public Crc64() : base(64) { }

        /// <summary>Initializes a new instance of the <see cref="Crc64"/> class and encrypts the specified stream.</summary>
        /// <inheritdoc cref="IChecksumAlgorithm.Encrypt(Stream)"/>
        public Crc64(Stream stream) : this() =>
            Encrypt(stream);

        /// <summary>Initializes a new instance of the <see cref="Crc64"/> class and encrypts the specified sequence of bytes.</summary>
        /// <inheritdoc cref="ChecksumAlgorithm(int, byte[])"/>
        public Crc64(byte[] bytes) : base(64, bytes) { }

        /// <summary>Initializes a new instance of the <see cref="Crc64"/> class and encrypts the specified text or file.</summary>
        /// <inheritdoc cref="ChecksumAlgorithm(int, string, bool)"/>
        public Crc64(string textOrFile, bool strIsFilePath) : base(64, textOrFile, strIsFilePath) { }

        /// <summary>Initializes a new instance of the <see cref="Crc64"/> class and encrypts the specified text.</summary>
        /// <inheritdoc cref="ChecksumAlgorithm(int, string)"/>
        public Crc64(string text) : base(64, text) { }

        /// <summary>Initializes a new instance of the <see cref="Crc64"/> class and encrypts the specified file.</summary>
        /// <inheritdoc cref="ChecksumAlgorithm(int, FileInfo)"/>
        public Crc64(FileInfo fileInfo) : base(64, fileInfo) { }

        /// <inheritdoc/>
        public override void Encrypt(Stream stream)
        {
            if (stream == null)
                throw new ArgumentNullException(nameof(stream));
            Current.ComputeHash(stream, out var num);
            HashNumber = Convert.ToUInt64(num);
            RawHash = CryptoUtils.GetByteArray(num, RawHashSize);
        }
    }
}
