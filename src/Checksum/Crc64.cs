namespace Roydl.Crypto.Checksum
{
    using System;
    using System.Collections.Generic;
    using System.Globalization;
    using System.IO;
    using System.Threading;
    using AbstractSamples;

    /// <summary>
    ///     Provides functionality to compute CRC-64/ECMA hashes.
    /// </summary>
    public sealed class Crc64 : ChecksumSample, IEquatable<Crc64>
    {
        /// <summary>
        ///     Gets the required hash length.
        /// </summary>
        public const int HashLength = 16;

        private const ulong Mask = 0xffffffffffffffffuL;
        private const ulong Poly = 0x42f0e1eba9ea3693uL;
        private const ulong Seed = 0x0000000000000000uL;
        private static volatile ulong[] _crcTable;

        /// <summary>
        ///     Gets the raw data of computed hash.
        /// </summary>
        public new ulong RawHash { get; private set; }

        private static IReadOnlyList<ulong> CrcTable
        {
            get
            {
                if (_crcTable != null)
                    return _crcTable;
                const ulong top = 1uL << (64 - 1);
                var table = new ulong[256];
                for (var i = 0; i < table.Length; i++)
                {
                    var ul = (ulong)i;
                    ul <<= 64 - 8;
                    for (var j = 0; j < 8; j++)
                        ul = (ul & top) != 0 ? (ul << 1) ^ Poly : ul << 1;
                    table[i] = ul & Mask;
                }
                Interlocked.CompareExchange(ref _crcTable, table, default);
                return _crcTable;
            }
        }

        /// <summary>
        ///     Initializes a new instance of the <see cref="Crc64"/> class.
        /// </summary>
        public Crc64() { }

        /// <summary>
        ///     Initializes a new instance of the <see cref="Crc64"/> class and encrypts
        ///     the specified stream.
        /// </summary>
        /// <param name="stream">
        ///     The stream to encrypt.
        /// </param>
        public Crc64(Stream stream) =>
            Encrypt(stream);

        /// <summary>
        ///     Initializes a new instance of the <see cref="Crc64"/> class and encrypts
        ///     the specified sequence of bytes.
        /// </summary>
        /// <param name="bytes">
        ///     The sequence of bytes to encrypt
        /// </param>
        public Crc64(byte[] bytes) =>
            Encrypt(bytes);

        /// <summary>
        ///     Initializes a new instance of the <see cref="Crc64"/> class and encrypts
        ///     the specified text or file.
        /// </summary>
        /// <param name="textOrFile">
        ///     The text or file to encrypt
        /// </param>
        /// <param name="strIsFilePath">
        ///     <see langword="true"/> if the specified value is a file path; otherwise,
        ///     <see langword="false"/>
        /// </param>
        public Crc64(string textOrFile, bool strIsFilePath)
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
        ///     The text to encrypt
        /// </param>
        public Crc64(string str) =>
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
            int i;
            var ul = Seed;
            while ((i = stream.ReadByte()) != -1)
                ul = (CrcTable[(int)(((ul >> 56) ^ (ulong)i) & 0xffuL)] ^ (ul << 8)) & Mask;
            RawHash = ul;
        }

        /// <summary>
        ///     Determines whether this instance have same values as the specified
        ///     <see cref="Crc64"/> instance.
        /// </summary>
        /// <param name="other">
        ///     The <see cref="Crc64"/> instance to compare.
        /// </param>
        public bool Equals(Crc64 other) =>
            other != null && RawHash == other.RawHash;

        /// <summary>
        ///     Determines whether this instance have same values as the specified
        ///     <see cref="object"/>.
        /// </summary>
        /// <param name="other">
        ///     The  <see cref="object"/> to compare.
        /// </param>
        public override bool Equals(object other) =>
            other is Crc64 item && Equals(item);

        /// <summary>
        ///     Returns the hash code for this instance.
        /// </summary>
        public override int GetHashCode() =>
            GetType().GetHashCode();

        /// <summary>
        ///     Converts the <see cref="RawHash"/> of this instance to its equivalent
        ///     string representation.
        /// </summary>
        public override string ToString() =>
            RawHash.ToString("x2", CultureInfo.CurrentCulture).PadLeft(HashLength, '0');

        /// <summary>
        ///     Determines whether two specified <see cref="Crc64"/> instances have same
        ///     values.
        /// </summary>
        /// <param name="left">
        ///     The first <see cref="Crc64"/> instance to compare.
        /// </param>
        /// <param name="right">
        ///     The second <see cref="Crc64"/> instance to compare.
        /// </param>
        public static bool operator ==(Crc64 left, Crc64 right) =>
            left?.Equals(right) ?? right is null;

        /// <summary>
        ///     Determines whether two specified <see cref="Crc64"/> instances have
        ///     different values.
        /// </summary>
        /// <param name="left">
        ///     The first <see cref="Crc64"/> instance to compare.
        /// </param>
        /// <param name="right">
        ///     The second <see cref="Crc64"/> instance to compare.
        /// </param>
        public static bool operator !=(Crc64 left, Crc64 right) =>
            !(left == right);
    }
}
