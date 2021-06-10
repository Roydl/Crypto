namespace Roydl.Crypto.Checksum
{
    using System;
    using System.IO;
    using System.Runtime.CompilerServices;
    using Internal;
    using Resources;

    /// <summary>Represents a 16-bit CRC configuration structure.</summary>
    public readonly struct CrcConfig16 : ICrcConfig<ushort>
    {
        private const int Columns = 1 << 8;
        private const int Rows = 1 << 3;

        /// <inheritdoc/>
        public int BitWidth { get; }

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
        public CrcConfig16(int bitWidth, ushort check, ushort poly, ushort init = default, bool refIn = false, bool refOut = false, ushort xorOut = default, ushort mask = default, bool skipValidation = false)
        {
            if (bitWidth < 8)
                throw new ArgumentOutOfRangeException(nameof(bitWidth), bitWidth, null);
            if (sizeof(ushort) < (int)MathF.Floor(bitWidth / 8f))
                throw new ArgumentException(ExceptionMessages.ArgumentBitsTypeRatioInvalid);
            if (mask == default)
                mask = NumericHelper.CreateBitMask<ushort>(bitWidth);
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
        public void ComputeHash(Stream stream, out ushort hash)
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
        public void ComputeHash(ReadOnlySpan<byte> bytes, out ushort hash)
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
        public unsafe void AppendData(ReadOnlySpan<byte> bytes, int len, ref ushort hash)
        {
            if (bytes.IsEmpty)
                throw new ArgumentNullException(nameof(bytes));
            var sum = hash;
            fixed (ushort* table = &Table.Span[0])
            {
                var i = 0;
                while (RefIn && len >= Rows)
                {
                    var x = sum;

                    sum = (ushort)(
                        table[5 * Columns + bytes[i + 2]] ^
                        table[4 * Columns + bytes[i + 3]] ^
                        table[3 * Columns + bytes[i + 4]] ^
                        table[2 * Columns + bytes[i + 5]] ^
                        table[1 * Columns + bytes[i + 6]] ^
                        table[0 * Columns + bytes[i + 7]]
                    );

                    sum ^= (ushort)(
                        table[7 * Columns + (((x >> 0) & 0xff) ^ bytes[i + 0])] ^
                        table[6 * Columns + (((x >> 8) & 0xff) ^ bytes[i + 1])]
                    );

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
        public unsafe void AppendData(byte value, ref ushort hash)
        {
            fixed (ushort* table = &Table.Span[0])
                AppendData(value, table, ref hash);
        }

        /// <inheritdoc/>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public void FinalizeHash(ref ushort hash)
        {
            if (!RefIn && RefOut)
                hash = hash.ReverseBits();
            else if (RefIn ^ RefOut)
                hash = (ushort)~hash;
            hash ^= XorOut;
        }

        /// <inheritdoc/>
        public bool IsValid(out ushort current)
        {
            ComputeHash(CrcConfig.ValidationBytes, out current);
            return current == Check;
        }

        /// <inheritdoc/>
        public bool IsValid() =>
            IsValid(out _);

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private unsafe void AppendData(byte value, ushort* table, ref ushort hash)
        {
            if (RefIn)
                hash = (ushort)(((hash >> 8) ^ table[value ^ (hash & 0xff)]) & Mask);
            else
                hash = (ushort)((table[((hash >> (BitWidth - 8)) ^ value) & 0xff] ^ (hash << 8)) & Mask);
        }

        private static ReadOnlyMemory<ushort> CreateTable(int width, ushort poly, ushort mask, bool refIn)
        {
            var top = (ushort)(1 << (width - 1));
            var rows = refIn ? Rows : 1;
            var mem = new ushort[rows * Columns].AsMemory();
            var span = mem.Span;
            for (var i = 0; i < Columns; i++)
            {
                var x = (ushort)i;
                for (var j = 0; j < rows; j++)
                {
                    if (refIn)
                        for (var k = 0; k < 8; k++)
                            x = (ushort)((x & 1) == 1 ? (x >> 1) ^ poly : x >> 1);
                    else
                    {
                        x <<= width - 8;
                        for (var k = 0; k < 8; k++)
                            x = (ushort)((x & top) != 0 ? (x << 1) ^ poly : x << 1);
                    }
                    span[j * Columns + i] = (ushort)(x & mask);
                }
            }
            return mem;
        }
    }
}
