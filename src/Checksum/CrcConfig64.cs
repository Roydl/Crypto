namespace Roydl.Crypto.Checksum
{
    using System;
    using System.IO;
    using Internal;
    using Resources;

    /// <summary>Represents a 64-bit CRC configuration structure.</summary>
    public readonly struct CrcConfig64 : ICrcConfig<ulong>
    {
        /// <inheritdoc/>
        public int Bits { get; }

        /// <inheritdoc/>
        public ulong Check { get; }

        /// <inheritdoc/>
        public ulong Mask { get; }

        /// <inheritdoc/>
        public ulong Poly { get; }

        /// <inheritdoc/>
        public ulong Init { get; }

        /// <inheritdoc/>
        public bool RefIn { get; }

        /// <inheritdoc/>
        public bool RefOut { get; }

        /// <inheritdoc/>
        public ulong XorOut { get; }

        /// <inheritdoc/>
        public ReadOnlyMemory<ulong> Table { get; }

        /// <summary>Creates a new configuration of the <see cref="CrcConfig64"/> struct.</summary>
        /// <inheritdoc cref="CrcConfig(int, byte, byte, byte, bool, bool, byte, byte, bool)"/>
        public CrcConfig64(int bits, ulong check, ulong poly, ulong init = default, bool refIn = false, bool refOut = false, ulong xorOut = default, ulong mask = default, bool skipValidation = false)
        {
            if (bits < 8)
                throw new ArgumentOutOfRangeException(nameof(bits), bits, null);
            if (sizeof(ulong) < (int)MathF.Floor(bits / 8f))
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
                CrcConfig.ThrowIfInvalid(this);
        }

        /// <inheritdoc/>
        public void ComputeHash(Stream stream, out ulong hash)
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
        public void ComputeHash(byte value, ref ulong hash)
        {
            var table = Table.Span;
            if (RefIn)
                hash = ((hash >> 8) ^ table[(int)(value ^ (hash & 0xffuL))]) & Mask;
            else
                hash = (table[(int)(((hash >> (Bits - 8)) ^ value) & 0xffuL)] ^ (hash << 8)) & Mask;
        }

        /// <inheritdoc/>
        public void FinalizeHash(ref ulong hash)
        {
            if (RefIn ^ RefOut)
                hash = ~hash;
            hash ^= XorOut;
        }

        /// <inheritdoc/>
        public bool IsValid(out ulong current) =>
            CrcConfig.IsValid(this, out current);

        /// <inheritdoc/>
        public bool IsValid() =>
            IsValid(out _);

        private static ulong CreateMask(int bits)
        {
            var mask = 0xffuL;
            var size = (int)MathF.Ceiling(bits / 8f);
            for (var i = 1; i < size; i++)
                mask ^= 0xffuL << (8 * i);
            return mask;
        }

        private static ReadOnlyMemory<ulong> CreateTable(int bits, ulong poly, ulong mask, bool refIn)
        {
            var top = 1uL << (bits - 1);
            var mem = new ulong[1 << 8].AsMemory();
            var span = mem.Span;
            for (var i = 0; i < span.Length; i++)
            {
                var x = (ulong)i;
                if (refIn)
                {
                    for (var k = 0; k < 8; k++)
                        x = (x & 1) == 1 ? (x >> 1) ^ poly : x >> 1;
                    span[i] = x & mask;
                    continue;
                }
                x <<= bits - 8;
                for (var j = 0; j < 8; j++)
                    x = (x & top) != 0 ? (x << 1) ^ poly : x << 1;
                span[i] = x & mask;
            }
            return mem;
        }
    }
}
