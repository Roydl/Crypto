namespace Roydl.Crypto.Checksum
{
    using System;
    using System.Collections.Generic;
    using System.IO;
    using System.Linq;
    using System.Threading;

    /// <summary>
    ///     Provides functionality to compute CRC-64/ECMA hashes.
    /// </summary>
    public sealed class Crc64 : ChecksumAlgorithm, IEquatable<Crc64>
    {
        private const int Bits = 64;

        private const ulong Mask = 0xffffffffffffffffuL,
                            Poly = 0x42f0e1eba9ea3693uL,
                            Seed = 0x0000000000000000uL;

        private const bool Swapped = false,
                           Reversed = false;

        private static volatile ulong[] _crcTable;

        /// <summary>
        ///     Gets the required hash length.
        /// </summary>
        public override int HashSize => 16;

        private static ReadOnlySpan<ulong> CrcTable
        {
            get
            {
                if (_crcTable == null)
                    Interlocked.CompareExchange(ref _crcTable, CreateTable(Poly, Swapped).ToArray(), null);
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
        ///     The sequence of bytes to encrypt.
        /// </param>
        public Crc64(byte[] bytes) =>
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
        ///     The text to encrypt.
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
            var ul = Seed;
            int i;
            while ((i = stream.ReadByte()) != -1)
                ComputeHash(ref ul, i, Swapped);
            FinalizeHash(ref ul, Reversed);
            HashNumber = ul;
            RawHash = CryptoUtils.GetBytesInverted(HashNumber, RawHashSize);
        }

        /// <summary>
        ///     Determines whether this instance have same values as the specified
        ///     <see cref="Crc64"/> instance.
        /// </summary>
        /// <param name="other">
        ///     The <see cref="Crc64"/> instance to compare.
        /// </param>
        public bool Equals(Crc64 other) =>
            base.Equals(other);

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

        private static IEnumerable<ulong> CreateTable(ulong poly, bool swapped)
        {
            const ulong top = unchecked((ulong)1 << (Bits - 1));
            for (var i = 0; i < 256; i++)
            {
                var x = (ulong)i;
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

        private static void ComputeHash(ref ulong crc, int value, bool swapped)
        {
            if (swapped)
            {
                crc = ((crc >> 8) ^ CrcTable[(int)((ulong)value ^ (crc & 0xff))]) & Mask;
                return;
            }
            crc = (CrcTable[(int)(((crc >> (Bits - 8)) ^ (ulong)value) & 0xffuL)] ^ (crc << 8)) & Mask;
        }

        private static void FinalizeHash(ref ulong crc, bool reversed)
        {
            if (reversed)
                crc = ~crc;
        }

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
