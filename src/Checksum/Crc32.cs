namespace Roydl.Crypto.Checksum
{
    using System;
    using System.Collections.Generic;
    using System.Globalization;
    using System.IO;
    using System.Threading;
    using AbstractSamples;

    /// <summary>
    ///     Provides functionality to compute CRC-32/ISO-HDLC hashes.
    /// </summary>
    public sealed class Crc32 : ChecksumSample, IEquatable<Crc32>
    {
        private const uint Mask = 0xffffffffu;
        private const uint Poly = 0xedb88320u;
        private const uint Seed = 0xffffffffu;
        private static volatile IReadOnlyList<uint> _crcTable;

        /// <summary>
        ///     Gets the required hash length.
        /// </summary>
        public override int HashLength => 8;

        /// <summary>
        ///     Gets the raw data of computed hash.
        /// </summary>
        public new uint RawHash { get; private set; }

        private static IReadOnlyList<uint> CrcTable
        {
            get
            {
                if (_crcTable != null)
                    return _crcTable;
                var table = new uint[256];
                for (var i = 0; i < table.Length; i++)
                {
                    var ui = (uint)i;
                    for (var j = 0; j < 8; j++)
                        ui = (ui & 1) == 1 ? (ui >> 1) ^ Poly : ui >> 1;
                    table[i] = ui & Mask;
                }
                Interlocked.CompareExchange(ref _crcTable, table, null);
                return _crcTable;
            }
        }

        /// <summary>
        ///     Initializes a new instance of the <see cref="Crc32"/> class.
        /// </summary>
        public Crc32() { }

        /// <summary>
        ///     Initializes a new instance of the <see cref="Crc32"/> class and encrypts
        ///     the specified stream.
        /// </summary>
        /// <param name="stream">
        ///     The stream to encrypt.
        /// </param>
        public Crc32(Stream stream) =>
            Encrypt(stream);

        /// <summary>
        ///     Initializes a new instance of the <see cref="Crc32"/> class and encrypts
        ///     the specified sequence of bytes.
        /// </summary>
        /// <param name="bytes">
        ///     The sequence of bytes to encrypt.
        /// </param>
        public Crc32(byte[] bytes) =>
            Encrypt(bytes);

        /// <summary>
        ///     Initializes a new instance of the <see cref="Crc32"/> class and encrypts
        ///     the specified text or file.
        /// </summary>
        /// <param name="textOrFile">
        ///     The text or file to encrypt.
        /// </param>
        /// <param name="strIsFilePath">
        ///     <see langword="true"/> if the specified value is a file path; otherwise,
        ///     <see langword="false"/>.
        /// </param>
        public Crc32(string textOrFile, bool strIsFilePath)
        {
            if (strIsFilePath)
            {
                EncryptFile(textOrFile);
                return;
            }
            Encrypt(textOrFile);
        }

        /// <summary>
        ///     Initializes a new instance of the <see cref="Crc32"/> class and encrypts
        ///     the specified text.
        /// </summary>
        /// <param name="str">
        ///     The text to encrypt.
        /// </param>
        public Crc32(string str) =>
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

            /* old code without table
            int i;
            var ui = Seed;
            while ((i = stream.ReadByte()) != -1)
            {
                ui ^= (uint)i;
                for (var j = 0; j < 8; j++)
                    ui = (uint)((ui >> 1) ^ (Polynomial & -(ui & 1)));
            }
            RawHash = ~ui;
            */

            int i;
            var ui = Seed;
            while ((i = stream.ReadByte()) != -1)
                ui = ((ui >> 8) ^ CrcTable[(int)(i ^ (ui & 0xff))]) & Mask;
            RawHash = ~ui;
        }

        /// <summary>
        ///     Determines whether this instance have same values as the specified
        ///     <see cref="Crc32"/> instance.
        /// </summary>
        /// <param name="other">
        ///     The <see cref="Crc32"/> instance to compare.
        /// </param>
        public bool Equals(Crc32 other) =>
            other != null && RawHash == other.RawHash;

        /// <summary>
        ///     Determines whether this instance have same values as the specified
        ///     <see cref="object"/>.
        /// </summary>
        /// <param name="other">
        ///     The  <see cref="object"/> to compare.
        /// </param>
        public override bool Equals(object other) =>
            other is Crc32 item && Equals(item);

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
        ///     Determines whether two specified <see cref="Crc32"/> instances have same
        ///     values.
        /// </summary>
        /// <param name="left">
        ///     The first <see cref="Crc32"/> instance to compare.
        /// </param>
        /// <param name="right">
        ///     The second <see cref="Crc32"/> instance to compare.
        /// </param>
        public static bool operator ==(Crc32 left, Crc32 right) =>
            left?.Equals(right) ?? right is null;

        /// <summary>
        ///     Determines whether two specified <see cref="Crc32"/> instances have
        ///     different values.
        /// </summary>
        /// <param name="left">
        ///     The first <see cref="Crc32"/> instance to compare.
        /// </param>
        /// <param name="right">
        ///     The second <see cref="Crc32"/> instance to compare.
        /// </param>
        public static bool operator !=(Crc32 left, Crc32 right) =>
            !(left == right);
    }
}
