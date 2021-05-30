namespace Roydl.Crypto.Checksum
{
    using System;
    using System.IO;
    using System.Numerics;

    /// <summary>Provides functionality to compute CRC-82/DARC hashes.</summary>
    public sealed class Crc82 : ChecksumAlgorithm<Crc82>
    {
        private static readonly CrcConfig<BigInteger> Current = CrcPreset.GetConfig(Crc82Preset.Default);

        /// <summary>Initializes a new instance of the <see cref="Crc82"/> class.</summary>
        public Crc82() : base(82) { }

        /// <summary>Initializes a new instance of the <see cref="Crc82"/> class and encrypts the specified stream.</summary>
        /// <inheritdoc cref="IChecksumAlgorithm.Encrypt(Stream)"/>
        public Crc82(Stream stream) : this() =>
            Encrypt(stream);

        /// <summary>Initializes a new instance of the <see cref="Crc82"/> class and encrypts the specified sequence of bytes.</summary>
        /// <inheritdoc cref="ChecksumAlgorithm(int, byte[])"/>
        public Crc82(byte[] bytes) : this() =>
            Encrypt(bytes);

        /// <summary>Initializes a new instance of the <see cref="Crc82"/> class and encrypts the specified text or file.</summary>
        /// <inheritdoc cref="ChecksumAlgorithm(int, string, bool)"/>
        public Crc82(string textOrFile, bool strIsFilePath) : this() =>
            Encrypt(textOrFile, strIsFilePath);

        /// <summary>Initializes a new instance of the <see cref="Crc82"/> class and encrypts the specified text.</summary>
        /// <inheritdoc cref="ChecksumAlgorithm(int, string)"/>
        public Crc82(string text) : this() =>
            Encrypt(text);

        /// <summary>Initializes a new instance of the <see cref="Crc82"/> class and encrypts the specified file.</summary>
        /// <inheritdoc cref="ChecksumAlgorithm(int, FileInfo)"/>
        public Crc82(FileInfo fileInfo) : this() =>
            Encrypt(fileInfo);

        /// <inheritdoc/>
        public override void Encrypt(Stream stream)
        {
            if (stream == null)
                throw new ArgumentNullException(nameof(stream));
            Current.ComputeHash(stream, out var num);
            HashNumber = (ulong)(num & 0xffffffffffffffffuL);
            var ba = num.ToByteArray();
            if (BitConverter.IsLittleEndian)
                Array.Reverse(ba);
            RawHash = ba;
        }
    }
}
