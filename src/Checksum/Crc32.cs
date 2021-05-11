namespace Roydl.Crypto.Checksum
{
    using System;
    using System.Collections.Generic;
    using System.IO;
    using System.Linq;
    using System.Threading;

    /// <summary>
    ///     Provides functionality to compute CRC-32/ISO-HDLC hashes.
    /// </summary>
    public sealed class Crc32 : ChecksumAlgorithm, IEquatable<Crc32>
    {
        private const int Bits = 32;

        private const uint Mask = 0xffffffffu,
                           Poly = 0xedb88320u,
                           Seed = 0xffffffffu;

        private const bool Swapped = true,
                           Reversed = true;

        private static volatile uint[] _crcTable;

        /// <summary>
        ///     Gets the required hash length.
        /// </summary>
        public override int HashSize => 8;

        private static ReadOnlySpan<uint> CrcTable
        {
            get
            {
                if (_crcTable == null)
                    Interlocked.CompareExchange(ref _crcTable, CreateTable(Poly, Swapped).ToArray(), null);
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
            int i;
            var ui = Seed;
            while ((i = stream.ReadByte()) != -1)
                ComputeHash(ref ui, i, Swapped);
            FinalizeHash(ref ui, Reversed);
            HashNumber = ui;
            RawHash = CryptoUtils.GetBytes(HashNumber, RawHashSize);
        }

        /// <summary>
        ///     Determines whether this instance have same values as the specified
        ///     <see cref="Crc32"/> instance.
        /// </summary>
        /// <param name="other">
        ///     The <see cref="Crc32"/> instance to compare.
        /// </param>
        public bool Equals(Crc32 other) =>
            base.Equals(other);

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

        private static IEnumerable<uint> CreateTable(uint poly, bool swapped)
        {
            const uint top = unchecked((uint)(1 << (Bits - 1)));
            for (var i = 0; i < 256; i++)
            {
                var x = (uint)i;
                if (swapped)
                {
                    for (var j = 0; j < 8; j++)
                        x = (x & 1) == 1 ? (x >> 1) ^ poly : x >> 1;
                    yield return x & Mask;
                    continue;
                }
                x <<= Bits - 8;
                for (var j = 0; j < 8; j++)
                    x = (x & top) != 0 ? (x << 1) ^ poly : x << 1;
                yield return x & Mask;
            }
        }

        private static void ComputeHash(ref uint crc, int value, bool swapped)
        {
            if (swapped)
            {
                crc = ((crc >> 8) ^ CrcTable[(int)(value ^ (crc & 0xff))]) & Mask;
                return;
            }
            crc = (CrcTable[(int)(((crc >> (Bits - 8)) ^ (uint)value) & 0xffu)] ^ (crc << 8)) & Mask;
        }

        private static void FinalizeHash(ref uint crc, bool reversed)
        {
            if (reversed)
                crc = ~crc;
        }

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
