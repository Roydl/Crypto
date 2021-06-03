namespace Roydl.Crypto.Checksum
{
    using System;
    using System.IO;
    using Internal;
    using Resources;

    /// <summary>Represents a 16-bit CRC configuration structure.</summary>
    public readonly struct CrcConfig16 : ICrcConfig<ushort>
    {
        /// <inheritdoc/>
        public int Bits { get; }

        /// <inheritdoc/>
        public ushort Check { get; }

        /// <inheritdoc/>
        public ushort Mask { get; }

        /// <inheritdoc/>
        public ushort Poly { get; }

        /// <inheritdoc/>
        public ushort Init { get; }

        /// <inheritdoc/>
        public bool RefIn { get; }

        /// <inheritdoc/>
        public bool RefOut { get; }

        /// <inheritdoc/>
        public ushort XorOut { get; }

        /// <inheritdoc/>
        public ReadOnlyMemory<ushort> Table { get; }

        /// <summary>Creates a new configuration of the <see cref="CrcConfig16"/> struct.</summary>
        /// <inheritdoc cref="CrcConfig(int, byte, byte, byte, bool, bool, byte, byte, bool)"/>
        public CrcConfig16(int bits, ushort check, ushort poly, ushort init = default, bool refIn = false, bool refOut = false, ushort xorOut = default, ushort mask = default, bool skipValidation = false)
        {
            if (bits < 8)
                throw new ArgumentOutOfRangeException(nameof(bits), bits, null);
            if (sizeof(ushort) < (int)MathF.Floor(bits / 8f))
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
        public void ComputeHash(Stream stream, out ushort hash)
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
        public void ComputeHash(byte value, ref ushort hash)
        {
            var table = Table.Span;
            if (RefIn)
                hash = (ushort)(((hash >> 8) ^ table[value ^ (hash & 0xff)]) & Mask);
            else
                hash = (ushort)((table[((hash >> (Bits - 8)) ^ value) & 0xff] ^ (hash << 8)) & Mask);
        }

        /// <inheritdoc/>
        public void FinalizeHash(ref ushort hash)
        {
            if (RefIn ^ RefOut)
                hash = (ushort)~hash;
            hash ^= XorOut;
        }

        /// <inheritdoc/>
        public bool IsValid(out ushort current) =>
            CrcConfig.IsValid(this, out current);

        /// <inheritdoc/>
        public bool IsValid() =>
            IsValid(out _);

        private static ushort CreateMask(int bits)
        {
            var mask = (ushort)0xff;
            var size = (int)MathF.Ceiling(bits / 8f);
            for (var i = 1; i < size; i++)
                mask ^= (ushort)(0xff << (8 * i));
            return mask;
        }

        private static ReadOnlyMemory<ushort> CreateTable(int bits, ushort poly, ushort mask, bool refIn)
        {
            var top = (ushort)(1 << (bits - 1));
            var mem = new ushort[1 << 8].AsMemory();
            var span = mem.Span;
            for (var i = 0; i < span.Length; i++)
            {
                var x = (ushort)i;
                if (refIn)
                {
                    for (var k = 0; k < 8; k++)
                        x = (ushort)((x & 1) == 1 ? (x >> 1) ^ poly : x >> 1);
                    span[i] = (ushort)(x & mask);
                    continue;
                }
                x <<= bits - 8;
                for (var j = 0; j < 8; j++)
                    x = (ushort)((x & top) != 0 ? (x << 1) ^ poly : x << 1);
                span[i] = (ushort)(x & mask);
            }
            return mem;
        }
    }
}
