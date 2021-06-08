namespace Roydl.Crypto.Checksum
{
    using System;
    using System.IO;
    using System.Numerics;
    using Internal;

    /// <summary>Represents a beyond 64-bit CRC configuration structure.
    ///     <para>Note that there is almost no size limit, but the computing power is significantly reduced.</para>
    /// </summary>
    public readonly struct CrcConfigBeyond : ICrcConfig<BigInteger>
    {
        /// <inheritdoc/>
        public int Bits { get; }

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
        public CrcConfigBeyond(int bits, BigInteger check, BigInteger poly, BigInteger init = default, bool refIn = false, bool refOut = false, BigInteger xorOut = default, BigInteger mask = default, bool skipValidation = false)
        {
            if (bits < 8)
                throw new ArgumentOutOfRangeException(nameof(bits), bits, null);
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
                CrcConfig.ThrowIfInvalid(this);
        }

        /// <inheritdoc cref="CrcConfigBeyond(int, BigInteger, BigInteger, BigInteger, bool, bool, BigInteger, BigInteger, bool)"/>
        public CrcConfigBeyond(int bits, string check, string poly, string init = default, bool refIn = false, bool refOut = false, string xorOut = default, string mask = default, bool skipValidation = false) : this(bits, check.ToBigInt(), poly.ToBigInt(), init.ToBigInt(), refIn, refOut, xorOut.ToBigInt(), mask.ToBigInt(), skipValidation) { }

        /// <inheritdoc/>
        public void ComputeHash(Stream stream, out BigInteger hash)
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
        public void ComputeHash(byte value, ref BigInteger hash)
        {
            var table = Table.Span;
            if (RefIn)
                hash = ((hash >> 8) ^ table[(int)(value ^ (hash & 0xff))]) & Mask;
            else
                hash = (table[(int)(((hash >> (Bits - 8)) ^ value) & 0xff)] ^ (hash << 8)) & Mask;
        }

        /// <inheritdoc/>
        public void FinalizeHash(ref BigInteger hash)
        {
            if (RefIn ^ RefOut)
                hash = ~hash;
            hash ^= XorOut;
        }

        /// <inheritdoc/>
        public bool IsValid(out BigInteger current) =>
            CrcConfig.IsValid(this, out current);

        /// <inheritdoc/>
        public bool IsValid() =>
            IsValid(out _);

        private static BigInteger CreateMask(int bits)
        {
            var mask = (BigInteger)0xff;
            var size = (int)MathF.Ceiling(bits / 8f);
            for (var i = 1; i < size; i++)
                mask ^= 0xff << (8 * i);
            return mask;
        }

        private static ReadOnlyMemory<BigInteger> CreateTable(int bits, BigInteger poly, BigInteger mask, bool refIn)
        {
            var top = (BigInteger)(1 << (bits - 1));
            var mem = new BigInteger[1 << 8].AsMemory();
            var span = mem.Span;
            for (var i = 0; i < span.Length; i++)
            {
                var x = (BigInteger)i;
                if (refIn)
                    for (var j = 0; j < 8; j++)
                        x = (x & 1) == 1 ? (x >> 1) ^ poly : x >> 1;
                else
                {
                    x <<= bits - 8;
                    for (var j = 0; j < 8; j++)
                        x = (x & top) != 0 ? (x << 1) ^ poly : x << 1;
                }
                span[i] = x & mask;
            }
            return mem;
        }
    }
}
