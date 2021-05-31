﻿namespace Roydl.Crypto.Checksum
{
    using System;
    using System.IO;

    /// <summary>Provides functionality to compute CRC-17/CAN-FD hashes.</summary>
    public sealed class Crc17 : ChecksumAlgorithm<Crc17>
    {
        private static readonly CrcConfig<uint> Current = CrcPreset.GetConfig(Crc17Preset.Default);

        /// <summary>Initializes a new instance of the <see cref="Crc17"/> class.</summary>
        public Crc17() : base(17, 5) { }

        /// <summary>Initializes a new instance of the <see cref="Crc17"/> class and encrypts the specified stream.</summary>
        /// <inheritdoc cref="IChecksumAlgorithm.Encrypt(Stream)"/>
        public Crc17(Stream stream) : this() =>
            Encrypt(stream);

        /// <summary>Initializes a new instance of the <see cref="Crc17"/> class and encrypts the specified sequence of bytes.</summary>
        /// <inheritdoc cref="ChecksumAlgorithm(int, byte[])"/>
        public Crc17(byte[] bytes) : this() =>
            Encrypt(bytes);

        /// <summary>Initializes a new instance of the <see cref="Crc17"/> class and encrypts the specified text or file.</summary>
        /// <inheritdoc cref="ChecksumAlgorithm(int, string, bool)"/>
        public Crc17(string textOrFile, bool strIsFilePath) : this() =>
            Encrypt(textOrFile, strIsFilePath);

        /// <summary>Initializes a new instance of the <see cref="Crc17"/> class and encrypts the specified text.</summary>
        /// <inheritdoc cref="ChecksumAlgorithm(int, string)"/>
        public Crc17(string text) : this() =>
            Encrypt(text);

        /// <summary>Initializes a new instance of the <see cref="Crc17"/> class and encrypts the specified file.</summary>
        /// <inheritdoc cref="ChecksumAlgorithm(int, FileInfo)"/>
        public Crc17(FileInfo fileInfo) : this() =>
            Encrypt(fileInfo);

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