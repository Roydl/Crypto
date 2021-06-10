namespace Roydl.Crypto.Checksum
{
    using System;
    using System.IO;
    using System.Runtime.CompilerServices;
    using Internal;
    using Resources;

    /// <summary>Represents a 64-bit CRC configuration structure.</summary>
    public readonly struct CrcConfig64 : ICrcConfig<ulong>
    {
        private const int Columns = 1 << 8;
        private const int Rows = 1 << 5;

        /// <inheritdoc/>
        public int BitWidth { get; }

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
        public CrcConfig64(int bitWidth, ulong check, ulong poly, ulong init = default, bool refIn = false, bool refOut = false, ulong xorOut = default, ulong mask = default, bool skipValidation = false)
        {
            if (bitWidth < 8)
                throw new ArgumentOutOfRangeException(nameof(bitWidth), bitWidth, null);
            if (sizeof(ulong) < (int)MathF.Floor(bitWidth / 8f))
                throw new ArgumentException(ExceptionMessages.ArgumentBitsTypeRatioInvalid);
            if (mask == default)
                mask = NumericHelper.CreateBitMask<ulong>(bitWidth);
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

        /// <inheritdoc/>
        public void ComputeHash(Stream stream, out ulong hash)
        {
            if (stream == null)
                throw new ArgumentNullException(nameof(stream));
            var sum = Init;
            Span<byte> bytes = stackalloc byte[stream.GetBufferSize()];
            int len;
            while ((len = stream.Read(bytes)) > 0)
                AppendData(bytes, len, ref sum);
            FinalizeHash(ref sum);
            hash = sum;
        }

        /// <inheritdoc/>
        public void ComputeHash(ReadOnlySpan<byte> bytes, out ulong hash)
        {
            if (bytes.IsEmpty)
                throw new ArgumentNullException(nameof(bytes));
            var sum = Init;
            AppendData(bytes, bytes.Length, ref sum);
            FinalizeHash(ref sum);
            hash = sum;
        }

        /// <inheritdoc/>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public unsafe void AppendData(ReadOnlySpan<byte> bytes, int len, ref ulong hash)
        {
            if (bytes.IsEmpty)
                throw new ArgumentNullException(nameof(bytes));
            var sum = hash;
            fixed (ulong* table = &Table.Span[0])
            {
                var i = 0;
                while (RefIn && len >= Rows)
                {
                    var x = sum;

                    sum = table[23 * Columns + bytes[i + 08]] ^
                          table[22 * Columns + bytes[i + 09]] ^
                          table[21 * Columns + bytes[i + 10]] ^
                          table[20 * Columns + bytes[i + 11]] ^
                          table[19 * Columns + bytes[i + 12]] ^
                          table[18 * Columns + bytes[i + 13]] ^
                          table[17 * Columns + bytes[i + 14]] ^
                          table[16 * Columns + bytes[i + 15]] ^
                          table[15 * Columns + bytes[i + 16]] ^
                          table[14 * Columns + bytes[i + 17]] ^
                          table[13 * Columns + bytes[i + 18]] ^
                          table[12 * Columns + bytes[i + 19]] ^
                          table[11 * Columns + bytes[i + 20]] ^
                          table[10 * Columns + bytes[i + 21]] ^
                          table[09 * Columns + bytes[i + 22]] ^
                          table[08 * Columns + bytes[i + 23]] ^
                          table[07 * Columns + bytes[i + 24]] ^
                          table[06 * Columns + bytes[i + 25]] ^
                          table[05 * Columns + bytes[i + 26]] ^
                          table[04 * Columns + bytes[i + 27]] ^
                          table[03 * Columns + bytes[i + 28]] ^
                          table[02 * Columns + bytes[i + 29]] ^
                          table[01 * Columns + bytes[i + 30]] ^
                          table[00 * Columns + bytes[i + 31]];

                    sum ^= table[31 * Columns + (((x >> 00) & 0xff) ^ bytes[i + 0])] ^
                           table[30 * Columns + (((x >> 08) & 0xff) ^ bytes[i + 1])] ^
                           table[29 * Columns + (((x >> 16) & 0xff) ^ bytes[i + 2])] ^
                           table[28 * Columns + (((x >> 24) & 0xff) ^ bytes[i + 3])] ^
                           table[27 * Columns + (((x >> 32) & 0xff) ^ bytes[i + 4])] ^
                           table[26 * Columns + (((x >> 40) & 0xff) ^ bytes[i + 5])] ^
                           table[25 * Columns + (((x >> 48) & 0xff) ^ bytes[i + 6])] ^
                           table[24 * Columns + (((x >> 56) & 0xff) ^ bytes[i + 7])];

                    i += Rows;
                    len -= Rows;
                    sum &= Mask;
                }
                while (--len >= 0)
                    AppendData(bytes[i++], table, ref sum);
            }
            hash = sum;
        }

        /// <inheritdoc/>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public unsafe void AppendData(byte value, ref ulong hash)
        {
            fixed (ulong* table = &Table.Span[0])
                AppendData(value, table, ref hash);
        }

        /// <inheritdoc/>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public void FinalizeHash(ref ulong hash)
        {
            if (!RefIn && RefOut)
                hash = hash.ReverseBits();
            else if (RefIn ^ RefOut)
                hash = ~hash;
            hash ^= XorOut;
        }

        /// <inheritdoc/>
        public bool IsValid(out ulong current)
        {
            ComputeHash(CrcConfig.ValidationBytes, out current);
            return current == Check;
        }

        /// <inheritdoc/>
        public bool IsValid() =>
            IsValid(out _);

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private unsafe void AppendData(byte value, ulong* table, ref ulong hash)
        {
            if (RefIn)
                hash = ((hash >> 8) ^ table[(int)(value ^ (hash & 0xff))]) & Mask;
            else
                hash = (table[(int)(((hash >> (BitWidth - 8)) ^ value) & 0xff)] ^ (hash << 8)) & Mask;
        }

        private static ReadOnlyMemory<ulong> CreateTable(int bitWidth, ulong poly, ulong mask, bool refIn)
        {
            var top = 1uL << (bitWidth - 1);
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
