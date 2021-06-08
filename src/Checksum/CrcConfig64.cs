namespace Roydl.Crypto.Checksum
{
    using System;
    using System.IO;
    using Internal;
    using Resources;

    /// <summary>Represents a 64-bit CRC configuration structure.</summary>
    public readonly struct CrcConfig64 : ICrcConfig<ulong>
    {
        private const int Columns = 1 << 8;
        private const int Rows = 1 << 5;

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
        public unsafe void ComputeHash(Stream stream, out ulong hash)
        {
            if (stream == null)
                throw new ArgumentNullException(nameof(stream));
            fixed (ulong* table = Table.Span)
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

                            sum = table[23 * Columns + buffer[i + 08]] ^
                                  table[22 * Columns + buffer[i + 09]] ^
                                  table[21 * Columns + buffer[i + 10]] ^
                                  table[20 * Columns + buffer[i + 11]] ^
                                  table[19 * Columns + buffer[i + 12]] ^
                                  table[18 * Columns + buffer[i + 13]] ^
                                  table[17 * Columns + buffer[i + 14]] ^
                                  table[16 * Columns + buffer[i + 15]] ^
                                  table[15 * Columns + buffer[i + 16]] ^
                                  table[14 * Columns + buffer[i + 17]] ^
                                  table[13 * Columns + buffer[i + 18]] ^
                                  table[12 * Columns + buffer[i + 19]] ^
                                  table[11 * Columns + buffer[i + 20]] ^
                                  table[10 * Columns + buffer[i + 21]] ^
                                  table[09 * Columns + buffer[i + 22]] ^
                                  table[08 * Columns + buffer[i + 23]] ^
                                  table[07 * Columns + buffer[i + 24]] ^
                                  table[06 * Columns + buffer[i + 25]] ^
                                  table[05 * Columns + buffer[i + 26]] ^
                                  table[04 * Columns + buffer[i + 27]] ^
                                  table[03 * Columns + buffer[i + 28]] ^
                                  table[02 * Columns + buffer[i + 29]] ^
                                  table[01 * Columns + buffer[i + 30]] ^
                                  table[00 * Columns + buffer[i + 31]];

                            sum ^= table[31 * Columns + (((x >> 00) & 0xff) ^ buffer[i + 0])] ^
                                   table[30 * Columns + (((x >> 08) & 0xff) ^ buffer[i + 1])] ^
                                   table[29 * Columns + (((x >> 16) & 0xff) ^ buffer[i + 2])] ^
                                   table[28 * Columns + (((x >> 24) & 0xff) ^ buffer[i + 3])] ^
                                   table[27 * Columns + (((x >> 32) & 0xff) ^ buffer[i + 4])] ^
                                   table[26 * Columns + (((x >> 40) & 0xff) ^ buffer[i + 5])] ^
                                   table[25 * Columns + (((x >> 48) & 0xff) ^ buffer[i + 6])] ^
                                   table[24 * Columns + (((x >> 56) & 0xff) ^ buffer[i + 7])];

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
        public void ComputeHash(byte value, ref ulong hash)
        {
            var table = Table.Span;
            if (RefIn)
                hash = ((hash >> 8) ^ table[(int)(value ^ (hash & 0xff))]) & Mask;
            else
                hash = (table[(int)(((hash >> (Bits - 8)) ^ value) & 0xff)] ^ (hash << 8)) & Mask;
        }

        /// <inheritdoc/>
        public void FinalizeHash(ref ulong hash)
        {
            if (!RefIn && RefOut)
                hash = hash.ReverseBits();
            else if (RefIn ^ RefOut)
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
            var rows = refIn ? Rows : 1;
            var mem = new ulong[rows * Columns].AsMemory();
            var span = mem.Span;
            for (var i = 0; i < Columns; i++)
            {
                var x = (ulong)i;
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
