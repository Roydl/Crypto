namespace Roydl.Crypto.Checksum
{
    using System;
    using System.Collections.Generic;
    using System.Globalization;
    using System.IO;
    using System.Threading;
    using AbstractSamples;

    /// <summary>
    ///     Provides functionality to compute CRC-16/AUG-CCITT hashes.
    /// </summary>
    public sealed class Crc16 : ChecksumSample, IEquatable<Crc16>
    {
        private const ushort Mask = 0xffff;
        private const ushort Poly = 0x1021;
        private const ushort Seed = 0x1d0f;
        private static volatile IReadOnlyList<ushort> _crcTable;

        /// <summary>
        ///     Gets the required hash length.
        /// </summary>
        public override int HashLength => 4;

        /// <summary>
        ///     Gets the raw data of computed hash.
        /// </summary>
        public new ushort RawHash { get; private set; }

        private static IReadOnlyList<ushort> CrcTable
        {
            get
            {
                if (_crcTable != null)
                    return _crcTable;
                var table = new ushort[256];
                for (var i = 0; i < table.Length; ++i)
                {
                    var us = ushort.MinValue;
                    var x = (ushort)(i << 8);
                    for (var j = 0; j < 8; ++j)
                    {
                        if (((us ^ x) & 0x8000) != 0)
                            us = (ushort)((us << 1) ^ Poly);
                        else
                            us <<= 1;
                        x <<= 1;
                    }
                    table[i] = (ushort)(us & Mask);
                }
                Interlocked.CompareExchange(ref _crcTable, table, null);
                return _crcTable;
            }
        }

        /// <summary>
        ///     Initializes a new instance of the <see cref="Crc16"/> class.
        /// </summary>
        public Crc16() { }

        /// <summary>
        ///     Initializes a new instance of the <see cref="Crc16"/> class and encrypts
        ///     the specified stream.
        /// </summary>
        /// <param name="stream">
        ///     The stream to encrypt.
        /// </param>
        public Crc16(Stream stream) =>
            Encrypt(stream);

        /// <summary>
        ///     Initializes a new instance of the <see cref="Crc16"/> class and encrypts
        ///     the specified sequence of bytes.
        /// </summary>
        /// <param name="bytes">
        ///     The sequence of bytes to encrypt.
        /// </param>
        public Crc16(byte[] bytes) =>
            Encrypt(bytes);

        /// <summary>
        ///     Initializes a new instance of the <see cref="Crc16"/> class and encrypts
        ///     the specified text or file.
        /// </summary>
        /// <param name="textOrFile">
        ///     The text or file to encrypt.
        /// </param>
        /// <param name="strIsFilePath">
        ///     <see langword="true"/> if the specified value is a file path; otherwise,
        ///     <see langword="false"/>.
        /// </param>
        public Crc16(string textOrFile, bool strIsFilePath)
        {
            if (strIsFilePath)
            {
                EncryptFile(textOrFile);
                return;
            }
            Encrypt(textOrFile);
        }

        /// <summary>
        ///     Initializes a new instance of the <see cref="Crc16"/> class and encrypts
        ///     the specified text.
        /// </summary>
        /// <param name="str">
        ///     The text to encrypt.
        /// </param>
        public Crc16(string str) =>
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
            var us = Seed;
            while ((i = stream.ReadByte()) != -1)
                us = (ushort)(((us << 8) ^ CrcTable[(us >> 8) ^ (0xff & i)]) & Mask);
            RawHash = us;
        }

        /// <summary>
        ///     Determines whether this instance have same values as the specified
        ///     <see cref="Crc16"/> instance.
        /// </summary>
        /// <param name="other">
        ///     The <see cref="Crc16"/> instance to compare.
        /// </param>
        public bool Equals(Crc16 other) =>
            other != null && RawHash == other.RawHash;

        /// <summary>
        ///     Determines whether this instance have same values as the specified
        ///     <see cref="object"/>.
        /// </summary>
        /// <param name="other">
        ///     The  <see cref="object"/> to compare.
        /// </param>
        public override bool Equals(object other) =>
            other is Crc16 item && Equals(item);

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
        ///     Determines whether two specified <see cref="Crc16"/> instances have same
        ///     values.
        /// </summary>
        /// <param name="left">
        ///     The first <see cref="Crc16"/> instance to compare.
        /// </param>
        /// <param name="right">
        ///     The second <see cref="Crc16"/> instance to compare.
        /// </param>
        public static bool operator ==(Crc16 left, Crc16 right) =>
            left?.Equals(right) ?? right is null;

        /// <summary>
        ///     Determines whether two specified <see cref="Crc16"/> instances have
        ///     different values.
        /// </summary>
        /// <param name="left">
        ///     The first <see cref="Crc16"/> instance to compare.
        /// </param>
        /// <param name="right">
        ///     The second <see cref="Crc16"/> instance to compare.
        /// </param>
        public static bool operator !=(Crc16 left, Crc16 right) =>
            !(left == right);
    }
}
