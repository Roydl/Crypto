namespace Roydl.Crypto.Checksum
{
    using System;
    using System.IO;
    using Internal;
    using Resources;

    /// <summary>Represents a 32-bit CRC configuration structure.</summary>
    public readonly struct CrcConfig32 : ICrcConfig<uint>
    {
        private const int Columns = 1 << 8;
        private const int Rows = 1 << 4;

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
        public unsafe void ComputeHash(Stream stream, out uint hash)
        {
            if (stream == null)
                throw new ArgumentNullException(nameof(stream));
            fixed (uint* table = Table.Span)
            {
                var bytes = new byte[stream.GetBufferSize()].AsSpan();
                var sum = Init;
                fixed (byte* buffer = bytes)
                {
                    int len;
                    while ((len = stream.Read(bytes)) > 0)
                    {
                        var i = 0;
                        while (RefIn && len >= Rows)
                        {
                            var x = sum;

                            sum = table[11 * Columns + buffer[i + 04]] ^
                                  table[10 * Columns + buffer[i + 05]] ^
                                  table[09 * Columns + buffer[i + 06]] ^
                                  table[08 * Columns + buffer[i + 07]] ^
                                  table[07 * Columns + buffer[i + 08]] ^
                                  table[06 * Columns + buffer[i + 09]] ^
                                  table[05 * Columns + buffer[i + 10]] ^
                                  table[04 * Columns + buffer[i + 11]] ^
                                  table[03 * Columns + buffer[i + 12]] ^
                                  table[02 * Columns + buffer[i + 13]] ^
                                  table[01 * Columns + buffer[i + 14]] ^
                                  table[00 * Columns + buffer[i + 15]];

                            sum ^= table[15 * Columns + (((x >> 0) & 0xff) ^ buffer[i + 0])] ^
                                   table[14 * Columns + (((x >> 8) & 0xff) ^ buffer[i + 1])] ^
                                   table[13 * Columns + (((x >> 16) & 0xff) ^ buffer[i + 2])] ^
                                   table[12 * Columns + (((x >> 24) & 0xff) ^ buffer[i + 3])];

                            i += Rows;
                            len -= Rows;
                            sum &= Mask;
                        }
                        while (--len >= 0)
                        {
                            var value = buffer[i++];
                            if (RefIn)
                                sum = ((sum >> 8) ^ table[(int)(value ^ (sum & 0xff))]) & Mask;
                            else
                                sum = (table[(int)(((sum >> (Bits - 8)) ^ value) & 0xff)] ^ (sum << 8)) & Mask;
                        }
                    }
                }
                hash = sum;
            }
            FinalizeHash(ref hash);
        }

        /// <inheritdoc/>
        public void ComputeHash(byte value, ref uint hash)
        {
            var table = Table.Span;
            if (RefIn)
                hash = ((hash >> 8) ^ table[(int)(value ^ (hash & 0xff))]) & Mask;
            else
                hash = (table[(int)(((hash >> (Bits - 8)) ^ value) & 0xff)] ^ (hash << 8)) & Mask;
        }

        /// <inheritdoc/>
        public void FinalizeHash(ref uint hash)
        {
            if (!RefIn && RefOut)
                hash = hash.ReverseBits();
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
            var rows = refIn ? Rows : 1;
            var mem = new uint[rows * Columns].AsMemory();
            var span = mem.Span;
            for (var i = 0; i < Columns; i++)
            {
                var x = (uint)i;
                for (var j = 0; j < rows; j++)
                {
                    if (refIn)
                        for (var k = 0; k < 8; k++)
                            x = (x & 1) == 1 ? (x >> 1) ^ poly : x >> 1;
                    else
                    {
                        x <<= bits - 8;
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
