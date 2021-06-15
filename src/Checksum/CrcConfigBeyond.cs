namespace Roydl.Crypto.Checksum
{
    using System;
    using System.IO;
    using System.Numerics;
    using System.Runtime.CompilerServices;
    using Internal;
    using Resources;

    /// <summary>Represents a beyond 64-bit CRC configuration structure.
    ///     <para>Note that there is almost no size limit, but the computing power is significantly reduced.</para>
    /// </summary>
    public readonly struct CrcConfigBeyond : ICrcConfig<BigInteger>
    {
        private const int Columns = 1 << 8;
        private const int Rows = 1 << 4;

        /// <inheritdoc/>
        public int BitWidth { get; }

        /// <inheritdoc/>
        public BigInteger Check { get; }

        /// <inheritdoc/>
        public BigInteger Mask { get; }

        /// <inheritdoc/>
        public BigInteger Poly { get; }

        /// <inheritdoc/>
        public BigInteger Init { get; }

        /// <inheritdoc/>
        public bool RefIn { get; }

        /// <inheritdoc/>
        public bool RefOut { get; }

        /// <inheritdoc/>
        public BigInteger XorOut { get; }

        /// <inheritdoc/>
        public ReadOnlyMemory<BigInteger> Table { get; }

        /// <summary>Creates a new configuration of the <see cref="CrcConfigBeyond"/> struct.</summary>
        /// <inheritdoc cref="CrcConfig(int, byte, byte, byte, bool, bool, byte, byte, bool)"/>
        public CrcConfigBeyond(int bitWidth, BigInteger check, BigInteger poly, BigInteger init = default, bool refIn = false, bool refOut = false, BigInteger xorOut = default, BigInteger mask = default, bool skipValidation = false)
        {
            if (bitWidth < 8)
                throw new ArgumentOutOfRangeException(nameof(bitWidth), bitWidth, null);
            if (mask == default)
                mask = NumericHelper.CreateBitMask<BigInteger>(bitWidth);
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
                CrcConfig.ThrowIfInvalid(this);
        }

        /// <inheritdoc cref="CrcConfigBeyond(int, BigInteger, BigInteger, BigInteger, bool, bool, BigInteger, BigInteger, bool)"/>
        public CrcConfigBeyond(int bitWidth, string check, string poly, string init = default, bool refIn = false, bool refOut = false, string xorOut = default, string mask = default, bool skipValidation = false) : this(bitWidth, check.ToBigInt(), poly.ToBigInt(), init.ToBigInt(), refIn, refOut, xorOut.ToBigInt(), mask.ToBigInt(), skipValidation) { }

        /// <inheritdoc/>
        public void ComputeHash(Stream stream, out BigInteger hash)
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
        public void ComputeHash(ReadOnlySpan<byte> bytes, out BigInteger hash)
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
        public void AppendData(ReadOnlySpan<byte> bytes, int len, ref BigInteger hash)
        {
            if (bytes.IsEmpty)
                throw new ArgumentException(ExceptionMessages.ArgumentEmpty, nameof(bytes));
            var sum = hash;
            var i = 0;
            var table = Table.Span;
            while (RefIn && len >= Rows)
            {
                var row = Rows;
                var pos = 0;
                var bts = 8;
                var cur = sum;
                sum = table[(int)(--row * Columns + ((cur & 0xff) ^ bytes[i + pos++]))];
                for (; pos < Rows; pos++)
                {
                    if (bts < BitWidth)
                    {
                        sum ^= table[(int)(--row * Columns + (((cur >> bts) & 0xff) ^ bytes[i + pos]))];
                        bts += 8;
                        continue;
                    }
                    sum ^= table[--row * Columns + bytes[i + pos]];
                }
                i += Rows;
                len -= Rows;
            }
            while (--len >= 0)
                AppendData(bytes[i++], table, ref sum);
            hash = sum;
        }

        /// <inheritdoc/>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public void AppendData(byte value, ref BigInteger hash)
        {
            var table = Table.Span;
            AppendData(value, table, ref hash);
        }

        /// <inheritdoc/>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public void FinalizeHash(ref BigInteger hash)
        {
            if (RefIn ^ RefOut)
                hash = ~hash;
            hash ^= XorOut;
        }

        /// <inheritdoc/>
        public bool IsValid(out BigInteger current)
        {
            ComputeHash(CrcConfig.ValidationBytes, out current);
            return current == Check;
        }

        /// <inheritdoc/>
        public bool IsValid() =>
            IsValid(out _);

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private void AppendData(byte value, ReadOnlySpan<BigInteger> table, ref BigInteger hash)
        {
            if (RefIn)
                hash = ((hash >> 8) ^ table[(int)(value ^ (hash & 0xff))]) & Mask;
            else
                hash = (table[(int)(((hash >> (BitWidth - 8)) ^ value) & 0xff)] ^ (hash << 8)) & Mask;
        }

        private static ReadOnlyMemory<BigInteger> CreateTable(int bitWidth, BigInteger poly, BigInteger mask, bool refIn)
        {
            var top = (BigInteger)(1 << (bitWidth - 1));
            var rows = refIn ? Rows : 1;
            var mem = new BigInteger[rows * Columns].AsMemory();
            var span = mem.Span;
            for (var i = 0; i < Columns; i++)
            {
                var x = (BigInteger)i;
                for (var j = 0; j < rows; j++)
                {
                    if (refIn)
                        for (var k = 0; k < 8; k++)
                            x = (x & 1) == 1 ? (x >> 1) ^ poly : x >> 1;
                    else
                    {
                        x <<= bitWidth - 8;
                        for (var k = 0; k < 8; k++)
                            x = (x & top) != 0 ? (x << 1) ^ poly : x << 1;
                    }
                    span[j * Columns + i] = x & mask;
                }
            }
            return mem;
        }
    }
}
