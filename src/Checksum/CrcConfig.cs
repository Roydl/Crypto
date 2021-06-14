namespace Roydl.Crypto.Checksum
{
    using System;
    using System.IO;
    using System.Runtime.CompilerServices;
    using Internal;
    using Resources;

    /// <summary>Represents a 8-bit CRC configuration structure.</summary>
    public readonly struct CrcConfig : ICrcConfig<byte>
    {
        internal static readonly byte[] ValidationBytes =
        {
            0x31, 0x32, 0x33,
            0x34, 0x35, 0x36,
            0x37, 0x38, 0x39
        };

        /// <inheritdoc/>
        public int BitWidth { get; }

        /// <inheritdoc/>
        public byte Check { get; }

        /// <inheritdoc/>
        public byte Mask { get; }

        /// <inheritdoc/>
        public byte Poly { get; }

        /// <inheritdoc/>
        public byte Init { get; }

        /// <inheritdoc/>
        public bool RefIn { get; }

        /// <inheritdoc/>
        public bool RefOut { get; }

        /// <inheritdoc/>
        public byte XorOut { get; }

        /// <inheritdoc/>
        public ReadOnlyMemory<byte> Table { get; }

        /// <summary>Creates a new configuration of the <see cref="CrcConfig"/> struct.</summary>
        /// <param name="bitWidth">The size in bits.</param>
        /// <param name="check">The test value that is used to check whether the algorithm is working correctly.</param>
        /// <param name="poly">The polynomial used to generate CRC hash table.</param>
        /// <param name="init">The seed from which the CRC register should be initialized at beginning of the calculation.</param>
        /// <param name="refIn"><see langword="true"/> to process the input bytes in big-endian bit order for the calculation; otherwise, <see langword="false"/>.</param>
        /// <param name="refOut"><see langword="true"/> to process the final output in big-endian bit order; otherwise, <see langword="false"/>.</param>
        /// <param name="xorOut">The value to xor with the final output.</param>
        /// <param name="mask">The mask, which is mostly the maximum type value.</param>
        /// <param name="skipValidation"><see langword="true"/> to skip the automated CRC validation (<b>not</b> recommended); otherwise, <see langword="false"/>.</param>
        /// <exception cref="ArgumentOutOfRangeException">bitWidth is less than 8.</exception>
        /// <exception cref="ArgumentException">bitWidth is too large for the current integral type of the hash code.</exception>
        /// <exception cref="InvalidDataException">The CRC validation failed.</exception>
        public CrcConfig(int bitWidth, byte check, byte poly, byte init = default, bool refIn = false, bool refOut = false, byte xorOut = default, byte mask = default, bool skipValidation = false)
        {
            if (bitWidth < 8)
                throw new ArgumentOutOfRangeException(nameof(bitWidth), bitWidth, null);
            if (sizeof(byte) < (int)MathF.Floor(bitWidth / 8f))
                throw new ArgumentException(ExceptionMessages.ArgumentBitsTypeRatioInvalid);
            if (mask == default)
                mask = NumericHelper.CreateBitMask<byte>(bitWidth);
            BitWidth = bitWidth;
            Check = check;
            Poly = poly;
            Init = init;
            RefIn = refIn;
            RefOut = refOut;
            XorOut = xorOut;
            Mask = mask;
            Table = CreateTable(bitWidth, poly, mask, refIn);
            if (!skipValidation)
                ThrowIfInvalid(this);
        }

        /// <inheritdoc/>
        public void ComputeHash(Stream stream, out byte hash)
        {
            if (stream == null)
                throw new ArgumentNullException(nameof(stream));
            if (!stream.CanRead)
                throw new NotSupportedException(ExceptionMessages.NotSupportedStreamRead);
            var sum = Init;
            Span<byte> bytes = stackalloc byte[stream.GetBufferSize()];
            int len;
            while ((len = stream.Read(bytes)) > 0)
                AppendData(bytes, len, ref sum);
            FinalizeHash(ref sum);
            hash = sum;
        }

        /// <inheritdoc/>
        public void ComputeHash(ReadOnlySpan<byte> bytes, out byte hash)
        {
            if (bytes.IsEmpty)
                throw new ArgumentException(ExceptionMessages.ArgumentEmpty, nameof(bytes));
            var sum = Init;
            AppendData(bytes, bytes.Length, ref sum);
            FinalizeHash(ref sum);
            hash = sum;
        }

        /// <inheritdoc/>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public unsafe void AppendData(ReadOnlySpan<byte> bytes, int len, ref byte hash)
        {
            if (bytes.IsEmpty)
                throw new ArgumentException(ExceptionMessages.ArgumentEmpty, nameof(bytes));
            var sum = hash;
            fixed (byte* table = &Table.Span[0])
            {
                var i = 0;
                while (--len >= 0)
                    AppendData(bytes[i++], table, ref sum);
            }
            hash = sum;
        }

        /// <inheritdoc/>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public unsafe void AppendData(byte value, ref byte hash)
        {
            fixed (byte* table = &Table.Span[0])
                AppendData(value, table, ref hash);
        }

        /// <inheritdoc/>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public void FinalizeHash(ref byte hash)
        {
            if (!RefIn && RefOut)
                hash = hash.ReverseBits();
            else if (RefIn ^ RefOut)
                hash = (byte)~hash;
            hash ^= XorOut;
        }

        /// <inheritdoc/>
        public bool IsValid(out byte current)
        {
            ComputeHash(ValidationBytes, out current);
            return current == Check;
        }

        /// <inheritdoc/>
        public bool IsValid() =>
            IsValid(out _);

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private unsafe void AppendData(byte value, byte* table, ref byte hash)
        {
            if (RefIn)
                hash = (byte)(((hash >> 8) ^ table[value ^ (hash & 0xff)]) & Mask);
            else
                hash = (byte)((table[((hash >> (BitWidth - 8)) ^ value) & 0xff] ^ (hash << 8)) & Mask);
        }

        private static ReadOnlyMemory<byte> CreateTable(int bitWidth, byte poly, byte mask, bool refIn)
        {
            var top = (byte)(1 << (bitWidth - 1));
            var mem = new byte[1 << 8].AsMemory();
            var span = mem.Span;
            for (var i = 0; i < mem.Length; i++)
            {
                var x = (byte)i;
                if (refIn)
                    for (var j = 0; j < 8; j++)
                        x = (byte)((x & 1) == 1 ? (x >> 1) ^ poly : x >> 1);
                else
                {
                    x <<= bitWidth - 8;
                    for (var j = 0; j < 8; j++)
                        x = (byte)((x & top) != 0 ? (x << 1) ^ poly : x << 1);
                }
                span[i] = (byte)(x & mask);
            }
            return mem;
        }

        internal static void ThrowIfInvalid<TValue>(ICrcConfig<TValue> item) where TValue : struct, IComparable, IFormattable
        {
            if (item.IsValid(out var current))
                return;
            var exc = new InvalidDataException(ExceptionMessages.InvalidDataCrcValidation);
            var size = (int)MathF.Ceiling(item.BitWidth / 4f);
            exc.Data.Add("Current", current.ToHexStr(size, true));
            exc.Data.Add("Expected", item.Check.ToHexStr(size, true));
            exc.Data.Add(nameof(item.Poly), item.Poly.ToHexStr(size, true));
            exc.Data.Add(nameof(item.Init), item.Init.ToHexStr(size, true));
            exc.Data.Add(nameof(item.RefIn), item.RefIn.ToString());
            exc.Data.Add(nameof(item.RefOut), item.RefOut.ToString());
            exc.Data.Add(nameof(item.XorOut), item.XorOut.ToHexStr(size, true));
            exc.Data.Add(nameof(item.Mask), item.Mask.ToHexStr(size, true));
            throw exc;
        }
    }
}
