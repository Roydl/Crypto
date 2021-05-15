﻿namespace Roydl.Crypto.Checksum
{
    using System;
    using System.IO;

    /// <summary>
    ///     Provides functionality to compute CRC-64/ECMA hashes.
    /// </summary>
    public sealed class Crc64 : ChecksumAlgorithm<Crc64>
    {
        private static readonly CrcConfig<ulong> Current = new(64, 0x42f0e1eba9ea3693uL, ulong.MinValue, false, false);

        /// <summary>
        ///     Initializes a new instance of the <see cref="Crc64"/> class.
        /// </summary>
        public Crc64() : base(64) { }

        /// <summary>
        ///     Initializes a new instance of the <see cref="Crc64"/> class and encrypts
        ///     the specified stream.
        /// </summary>
        /// <param name="stream">
        ///     The stream to encrypt.
        /// </param>
        public Crc64(Stream stream) : this() =>
            Encrypt(stream);

        /// <summary>
        ///     Initializes a new instance of the <see cref="Crc64"/> class and encrypts
        ///     the specified sequence of bytes.
        /// </summary>
        /// <param name="bytes">
        ///     The sequence of bytes to encrypt.
        /// </param>
        public Crc64(byte[] bytes) : this() =>
            Encrypt(bytes);

        /// <summary>
        ///     Initializes a new instance of the <see cref="Crc64"/> class and encrypts
        ///     the specified text or file.
        /// </summary>
        /// <param name="textOrFile">
        ///     The text or file to encrypt.
        /// </param>
        /// <param name="strIsFilePath">
        ///     <see langword="true"/> if the specified value is a file path; otherwise,
        ///     <see langword="false"/>.
        /// </param>
        public Crc64(string textOrFile, bool strIsFilePath) : this()
        {
            if (strIsFilePath)
            {
                EncryptFile(textOrFile);
                return;
            }
            Encrypt(textOrFile);
        }

        /// <summary>
        ///     Initializes a new instance of the <see cref="Crc64"/> class and encrypts
        ///     the specified text.
        /// </summary>
        /// <param name="str">
        ///     The text to encrypt.
        /// </param>
        public Crc64(string str) : this() =>
            Encrypt(str);

        /// <summary>
        ///     Encrypts the specified stream.
        /// </summary>
        /// <param name="stream">
        ///     The stream to encrypt.
        /// </param>
        public override void Encrypt(Stream stream)
        {
            if (stream == null)
                throw new ArgumentNullException(nameof(stream));
            Current.ComputeHash(stream, out var num);
            HashNumber = Convert.ToUInt64(num);
            RawHash = CryptoUtils.GetByteArray(Convert.ToUInt64(num), RawHashSize);
        }
    }
}
