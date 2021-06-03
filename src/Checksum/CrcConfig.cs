namespace Roydl.Crypto.Checksum
{
    using System;
    using System.Collections.Generic;
    using System.IO;
    using Internal;
    using Resources;

    /// <summary>Represents a 8-bit CRC configuration structure.</summary>
    public readonly struct CrcConfig : ICrcConfig<byte>
    {
        /// <inheritdoc/>
        public int Bits { get; }

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
        /// <param name="bits">The size in bits.</param>
        /// <param name="check">The test value that is used to check whether the algorithm is working correctly.</param>
        /// <param name="poly">The polynomial used to generate CRC hash table.</param>
        /// <param name="init">The seed from which the CRC register should be initialized at beginning of the calculation.</param>
        /// <param name="refIn"><see langword="true"/> to process the input bytes in big-endian bit order for the calculation; otherwise, <see langword="false"/>.</param>
        /// <param name="refOut"><see langword="true"/> to process the final output in big-endian bit order; otherwise, <see langword="false"/>.</param>
        /// <param name="xorOut">The value to xor with the final output.</param>
        /// <param name="mask">The mask, which is mostly the maximum type value.</param>
        /// <param name="skipValidation"><see langword="true"/> to skip the automated CRC validation (<b>not</b> recommended); otherwise, <see langword="false"/>.</param>
        /// <exception cref="ArgumentOutOfRangeException">bits are less than 8.</exception>
        /// <exception cref="ArgumentException">bits are larger than byte type allows.</exception>
        /// <exception cref="InvalidDataException">The CRC validation failed.</exception>
        public CrcConfig(int bits, byte check, byte poly, byte init = default, bool refIn = false, bool refOut = false, byte xorOut = default, byte mask = default, bool skipValidation = false)
        {
            if (bits < 8)
                throw new ArgumentOutOfRangeException(nameof(bits), bits, null);
            if (sizeof(byte) < (int)MathF.Floor(bits / 8f))
                throw new ArgumentException(ExceptionMessages.ArgumentBitsTypeRatioInvalid);
            if (mask == default)
                mask = CreateMask(bits);
            Bits = bits;
            Check = check;
            Poly = poly;
            Init = init;
            RefIn = refIn;
            RefOut = refOut;
            XorOut = xorOut;
            Mask = mask;
            Table = CreateTable(bits, poly, mask, refIn);
            if (!skipValidation)
                ThrowIfInvalid(this);
        }

        /// <inheritdoc/>
        public void ComputeHash(Stream stream, out byte hash)
        {
            if (stream == null)
                throw new ArgumentNullException(nameof(stream));
            hash = Init;
            var span = new byte[stream.GetBufferSize()].AsSpan();
            int len;
            while ((len = stream.Read(span)) > 0)
            {
                for (var i = 0; i < len; i++)
                    ComputeHash(span[i], ref hash);
            }
            FinalizeHash(ref hash);
        }

        /// <inheritdoc/>
        public void ComputeHash(byte value, ref byte hash)
        {
            var table = Table.Span;
            if (RefIn)
                hash = (byte)(((hash >> 8) ^ table[value ^ (hash & 0xff)]) & Mask);
            else
                hash = (byte)((table[((hash >> (Bits - 8)) ^ value) & 0xff] ^ (hash << 8)) & Mask);
        }

        /// <inheritdoc/>
        public void FinalizeHash(ref byte hash)
        {
            if (RefIn ^ RefOut)
                hash = (byte)~hash;
            hash ^= XorOut;
        }

        /// <inheritdoc/>
        public bool IsValid(out byte current) =>
            IsValid(this, out current);

        /// <inheritdoc/>
        public bool IsValid() =>
            IsValid(out _);

        internal static bool IsValid<T>(ICrcConfig<T> item, out T current) where T : struct, IComparable, IFormattable
        {
            using var ms = new MemoryStream(new byte[]
            {
                0x31, 0x32, 0x33,
                0x34, 0x35, 0x36,
                0x37, 0x38, 0x39
            });
            item.ComputeHash(ms, out current);
            return EqualityComparer<T>.Default.Equals(current, item.Check);
        }

        internal static void ThrowIfInvalid<T>(ICrcConfig<T> item) where T : struct, IComparable, IFormattable
        {
            if (item.IsValid(out var current))
                return;
            var exc = new InvalidDataException(ExceptionMessages.InvalidDataCrcValidation);
            var size = (int)MathF.Ceiling(item.Bits / 4f);
            exc.Data.Add("Current", current.ToHexStr(size, true));
            exc.Data.Add("Expected", item.Check.ToHexStr(size, true));
            exc.Data.Add(nameof(Poly), item.Poly.ToHexStr(size, true));
            exc.Data.Add(nameof(Init), item.Init.ToHexStr(size, true));
            exc.Data.Add(nameof(RefIn), item.RefIn.ToString());
            exc.Data.Add(nameof(RefOut), item.RefOut.ToString());
            exc.Data.Add(nameof(XorOut), item.XorOut.ToHexStr(size, true));
            exc.Data.Add(nameof(Mask), item.Mask.ToHexStr(size, true));
            throw exc;
        }

        private static byte CreateMask(int bits)
        {
            var mask = (byte)0xff;
            var size = (int)MathF.Ceiling(bits / 8f);
            for (var i = 1; i < size; i++)
                mask ^= (byte)(0xff << (8 * i));
            return mask;
        }

        private static ReadOnlyMemory<byte> CreateTable(int bits, byte poly, byte mask, bool refIn)
        {
            var top = (byte)(1 << (bits - 1));
            var mem = new byte[1 << 8].AsMemory();
            var span = mem.Span;
            for (var i = 0; i < span.Length; i++)
            {
                var x = (byte)i;
                if (refIn)
                {
                    for (var k = 0; k < 8; k++)
                        x = (byte)((x & 1) == 1 ? (x >> 1) ^ poly : x >> 1);
                    span[i] = (byte)(x & mask);
                    continue;
                }
                x <<= bits - 8;
                for (var j = 0; j < 8; j++)
                    x = (byte)((x & top) != 0 ? (x << 1) ^ poly : x << 1);
                span[i] = (byte)(x & mask);
            }
            return mem;
        }
    }
}
