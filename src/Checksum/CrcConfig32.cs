namespace Roydl.Crypto.Checksum
{
    using System;
    using System.IO;
    using System.Runtime.CompilerServices;
    using Internal;
    using Resources;

    /// <summary>Represents a 32-bit CRC configuration structure.</summary>
    public readonly struct CrcConfig32 : ICrcConfig<uint>
    {
        private const int Columns = 1 << 8;
        private const int Rows = 1 << 4;

        /// <inheritdoc/>
        public int BitWidth { get; }

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
        public CrcConfig32(int bitWidth, uint check, uint poly, uint init = default, bool refIn = false, bool refOut = false, uint xorOut = default, uint mask = default, bool skipValidation = false)
        {
            if (bitWidth < 8)
                throw new ArgumentOutOfRangeException(nameof(bitWidth), bitWidth, null);
            if (sizeof(uint) < (int)MathF.Floor(bitWidth / 8f))
                throw new ArgumentException(ExceptionMessages.ArgumentBitsTypeRatioInvalid);
            if (mask == default)
                mask = Helper.CreateBitMask<uint>(bitWidth);
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
                CrcConfig.InternalThrowIfInvalid(this);
        }

        /// <inheritdoc/>
        public void ComputeHash(Stream stream, out uint hash)
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
        public void ComputeHash(ReadOnlySpan<byte> bytes, out uint hash)
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
        public unsafe void AppendData(ReadOnlySpan<byte> bytes, int len, ref uint hash)
        {
            if (bytes.IsEmpty)
                throw new ArgumentNullException(nameof(bytes));
            var sum = hash;
            fixed (uint* table = &Table.Span[0])
            {
                var i = 0;
                while (RefIn && len >= Rows)
                {
                    var x = sum;

                    sum = table[11 * Columns + bytes[i + 04]] ^
                          table[10 * Columns + bytes[i + 05]] ^
                          table[09 * Columns + bytes[i + 06]] ^
                          table[08 * Columns + bytes[i + 07]] ^
                          table[07 * Columns + bytes[i + 08]] ^
                          table[06 * Columns + bytes[i + 09]] ^
                          table[05 * Columns + bytes[i + 10]] ^
                          table[04 * Columns + bytes[i + 11]] ^
                          table[03 * Columns + bytes[i + 12]] ^
                          table[02 * Columns + bytes[i + 13]] ^
                          table[01 * Columns + bytes[i + 14]] ^
                          table[00 * Columns + bytes[i + 15]];

                    sum ^= table[15 * Columns + (((x >> 00) & 0xff) ^ bytes[i + 0])] ^
                           table[14 * Columns + (((x >> 08) & 0xff) ^ bytes[i + 1])] ^
                           table[13 * Columns + (((x >> 16) & 0xff) ^ bytes[i + 2])] ^
                           table[12 * Columns + (((x >> 24) & 0xff) ^ bytes[i + 3])];

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
        public unsafe void AppendData(byte value, ref uint hash)
        {
            fixed (uint* table = &Table.Span[0])
                AppendData(value, table, ref hash);
        }

        /// <inheritdoc/>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
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
            CrcConfig.InternalIsValid(this, out current);

        /// <inheritdoc/>
        public bool IsValid() =>
            IsValid(out _);

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private unsafe void AppendData(byte value, uint* table, ref uint hash)
        {
            if (RefIn)
                hash = ((hash >> 8) ^ table[(int)(value ^ (hash & 0xff))]) & Mask;
            else
                hash = (table[(int)(((hash >> (BitWidth - 8)) ^ value) & 0xff)] ^ (hash << 8)) & Mask;
        }

        private static ReadOnlyMemory<uint> CreateTable(int bitWidth, uint poly, uint mask, bool refIn)
        {
            var top = 1u << (bitWidth - 1);
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
