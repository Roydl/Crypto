namespace Roydl.Crypto.Checksum
{
    using System;
    using System.Collections.Generic;
    using System.IO;
    using System.Linq;
    using System.Threading;

    /// <summary>
    ///     Provides functionality to compute CRC-16/AUG-CCITT hashes.
    /// </summary>
    public sealed class Crc16 : ChecksumAlgorithm, IEquatable<Crc16>
    {
        private const int Bits = 16;

        private const ushort Mask = 0xffff,
                             Poly = 0x1021,
                             Seed = 0x1d0f;

        private const bool Swapped = false,
                           Reversed = false;

        private static volatile ushort[] _crcTable;

        /// <summary>
        ///     Gets the required hash length.
        /// </summary>
        public override int HashSize => 4;

        private static ReadOnlySpan<ushort> CrcTable
        {
            get
            {
                if (_crcTable == null)
                    Interlocked.CompareExchange(ref _crcTable, CreateTable(Poly, Swapped).ToArray(), null);
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
                ComputeHash(ref us, i, Swapped);
            FinalizeHash(ref us, Reversed);
            HashNumber = us;
            RawHash = CryptoUtils.GetBytes(HashNumber, RawHashSize);
        }

        /// <summary>
        ///     Determines whether this instance have same values as the specified
        ///     <see cref="Crc16"/> instance.
        /// </summary>
        /// <param name="other">
        ///     The <see cref="Crc16"/> instance to compare.
        /// </param>
        public bool Equals(Crc16 other) =>
            base.Equals(other);

        /// <summary>
        ///     Determines whether this instance have same values as the specified
        ///     <see cref="object"/>.
        /// </summary>
        /// <param name="other">
        ///     The <see cref="object"/> to compare.
        /// </param>
        public override bool Equals(object other) =>
            other is Crc16 item && Equals(item);

        /// <summary>
        ///     Returns the hash code for this instance.
        /// </summary>
        public override int GetHashCode() =>
            GetType().GetHashCode();

        private static IEnumerable<ushort> CreateTable(ushort poly, bool swapped)
        {
            const ushort top = unchecked(1 << (Bits - 1));
            for (var i = 0; i < 256; i++)
            {
                var x = (ushort)i;
                if (swapped)
                {
                    for (var j = 0; j < 8; j++)
                        x = (ushort)((x & 1) == 1 ? (x >> 1) ^ poly : x >> 1);
                    yield return (ushort)(x & Mask);
                    continue;
                }
                x <<= Bits - 8;
                for (var j = 0; j < 8; j++)
                    x = (ushort)((x & top) != 0 ? (x << 1) ^ poly : x << 1);
                yield return (ushort)(x & Mask);
            }
        }

        private static void ComputeHash(ref ushort crc, int value, bool swapped)
        {
            if (swapped)
            {
                crc = (ushort)((crc >> 8) ^ (CrcTable[value ^ (crc & 0xff)] & Mask));
                return;
            }
            crc = (ushort)(((crc << (Bits - 8)) ^ CrcTable[(crc >> 8) ^ (0xff & value)]) & Mask);
        }

        private static void FinalizeHash(ref ushort crc, bool reversed)
        {
            if (reversed)
                crc = (ushort)~crc;
        }

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
