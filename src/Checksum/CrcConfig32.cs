namespace Roydl.Crypto.Checksum
{
    using System;
    using System.IO;
    using System.Linq;
    using Internal;
    using Resources;

    /// <summary>Represents a 32-bit CRC configuration structure.</summary>
    public readonly struct CrcConfig32 : ICrcConfig<uint>
    {
        /// <inheritdoc/>
        public int Bits { get; }

        /// <inheritdoc/>
        public uint Check { get; }

        /// <inheritdoc/>
        public uint Mask { get; }

        /// <inheritdoc/>
        public uint Poly { get; }

        /// <inheritdoc/>
        public uint Init { get; }

        /// <inheritdoc/>
        public bool RefIn { get; }

        /// <inheritdoc/>
        public bool RefOut { get; }

        /// <inheritdoc/>
        public uint XorOut { get; }

        /// <inheritdoc/>
        public ReadOnlyMemory<uint> Table { get; }

        /// <summary>Creates a new configuration of the <see cref="CrcConfig32"/> struct.</summary>
        /// <inheritdoc cref="CrcConfig(int, byte, byte, byte, bool, bool, byte, byte, bool)"/>
        public CrcConfig32(int bits, uint check, uint poly, uint init = default, bool refIn = false, bool refOut = false, uint xorOut = default, uint mask = default, bool skipValidation = false)
        {
            if (bits < 8)
                throw new ArgumentOutOfRangeException(nameof(bits), bits, null);
            if (sizeof(uint) < (int)MathF.Floor(bits / 8f))
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
        public void ComputeHash(Stream stream, out uint hash)
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
        public void ComputeHash(byte value, ref uint hash)
        {
            var table = Table.Span;
            if (RefIn)
                hash = ((hash >> 8) ^ table[(int)(value ^ (hash & 0xffu))]) & Mask;
            else
                hash = (table[(int)(((hash >> (Bits - 8)) ^ value) & 0xffu)] ^ (hash << 8)) & Mask;
        }

        /// <inheritdoc/>
        public void FinalizeHash(ref uint hash)
        {
            if (!RefIn && RefOut)
                BitsReverseSlow(ref hash);
            else if (RefIn ^ RefOut)
                hash = ~hash;
            hash ^= XorOut;
        }

        /// <inheritdoc/>
        public bool IsValid(out uint current) =>
            CrcConfig.IsValid(this, out current);

        /// <inheritdoc/>
        public bool IsValid() =>
            IsValid(out _);

        private void BitsReverseSlow(ref uint hash)
        {
            var bitstr = Convert.ToString(hash, 2);
            var size = bitstr.Length;
            while (size % 4 != 0)
                size++;
            if (bitstr.Length < size)
                bitstr = bitstr.PadLeft(size, '0');
            bitstr = new string(bitstr.Reverse().ToArray());
            hash = Convert.ToUInt32(bitstr, 2) & Mask;
        }

        private static uint CreateMask(int bits)
        {
            var mask = 0xffu;
            var size = (int)MathF.Ceiling(bits / 8f);
            for (var i = 1; i < size; i++)
                mask ^= 0xffu << (8 * i);
            return mask;
        }

        private static ReadOnlyMemory<uint> CreateTable(int bits, uint poly, uint mask, bool refIn)
        {
            var top = 1u << (bits - 1);
            var mem = new uint[1 << 8].AsMemory();
            var span = mem.Span;
            for (var i = 0; i < span.Length; i++)
            {
                var x = (uint)i;
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
