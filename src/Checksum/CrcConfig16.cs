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
        private const int Rows = 1 << 4;

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
            ArgumentNullException.ThrowIfNull(stream);
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
        public void ComputeHash(ReadOnlySpan<byte> bytes, out ushort hash)
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
        public unsafe void AppendData(ReadOnlySpan<byte> bytes, int len, ref ushort hash)
        {
            if (bytes.IsEmpty)
                throw new ArgumentException(ExceptionMessages.ArgumentEmpty, nameof(bytes));
            var sum = hash;
            fixed (ushort* table = Table.Span)
                fixed (byte* input = bytes)
                {
                    var i = 0;
                    switch (RefIn)
                    {
                        // Non-reflected sliced-by-16 (16-bit only; L^16(crc) derivation relies on 16-bit shift-out behavior)
                        // Unlike reflected, carry bytes and data bytes use separate table rows and cannot share a combined
                        // index — 18 reads vs. 16.
                        case false when BitWidth == 16:
                        {
                            while (len >= Rows)
                            {
                                var row = Rows;
                                var pos = 0;
                                
                                // Note: byte order is reversed compared to reflected (high byte → high row)
                                sum = (ushort)((Unsafe.Read<ushort>(table + 15 * Columns + (sum >> 8)) ^
                                                Unsafe.Read<ushort>(table + 14 * Columns + (sum & 0xff)) ^
                                                Unsafe.Read<ushort>(table + --row * Columns + Unsafe.Read<byte>(input + i + pos++)) ^
                                                Unsafe.Read<ushort>(table + --row * Columns + Unsafe.Read<byte>(input + i + pos++)) ^
                                                Unsafe.Read<ushort>(table + --row * Columns + Unsafe.Read<byte>(input + i + pos++)) ^
                                                Unsafe.Read<ushort>(table + --row * Columns + Unsafe.Read<byte>(input + i + pos++)) ^
                                                Unsafe.Read<ushort>(table + --row * Columns + Unsafe.Read<byte>(input + i + pos++)) ^
                                                Unsafe.Read<ushort>(table + --row * Columns + Unsafe.Read<byte>(input + i + pos++)) ^
                                                Unsafe.Read<ushort>(table + --row * Columns + Unsafe.Read<byte>(input + i + pos++)) ^
                                                Unsafe.Read<ushort>(table + --row * Columns + Unsafe.Read<byte>(input + i + pos++)) ^
                                                Unsafe.Read<ushort>(table + --row * Columns + Unsafe.Read<byte>(input + i + pos++)) ^
                                                Unsafe.Read<ushort>(table + --row * Columns + Unsafe.Read<byte>(input + i + pos++)) ^
                                                Unsafe.Read<ushort>(table + --row * Columns + Unsafe.Read<byte>(input + i + pos++)) ^
                                                Unsafe.Read<ushort>(table + --row * Columns + Unsafe.Read<byte>(input + i + pos++)) ^
                                                Unsafe.Read<ushort>(table + --row * Columns + Unsafe.Read<byte>(input + i + pos++)) ^
                                                Unsafe.Read<ushort>(table + --row * Columns + Unsafe.Read<byte>(input + i + pos++)) ^
                                                Unsafe.Read<ushort>(table + --row * Columns + Unsafe.Read<byte>(input + i + pos++)) ^
                                                Unsafe.Read<ushort>(table + --row * Columns + Unsafe.Read<byte>(input + i + pos))) & Mask);
                                
                                i += Rows;
                                len -= Rows;
                            }
                            break;
                        }
                        case true:
                        {
                            /*
                                replacing `i + pos++` with `i++` or replacing `--row` with
                                constants, both lead to a significant drop in performance
                            */
                            while (len >= Rows)
                            {
                                var row = Rows;
                                var pos = 0;
                                sum = (ushort)((Unsafe.Read<ushort>(table + --row * Columns + (sum >> 00 & 0xff ^ Unsafe.Read<byte>(input + i + pos++))) ^
                                                Unsafe.Read<ushort>(table + --row * Columns + (sum >> 08 & 0xff ^ Unsafe.Read<byte>(input + i + pos++))) ^
                                                Unsafe.Read<ushort>(table + --row * Columns + Unsafe.Read<byte>(input + i + pos++)) ^
                                                Unsafe.Read<ushort>(table + --row * Columns + Unsafe.Read<byte>(input + i + pos++)) ^
                                                Unsafe.Read<ushort>(table + --row * Columns + Unsafe.Read<byte>(input + i + pos++)) ^
                                                Unsafe.Read<ushort>(table + --row * Columns + Unsafe.Read<byte>(input + i + pos++)) ^
                                                Unsafe.Read<ushort>(table + --row * Columns + Unsafe.Read<byte>(input + i + pos++)) ^
                                                Unsafe.Read<ushort>(table + --row * Columns + Unsafe.Read<byte>(input + i + pos++)) ^
                                                Unsafe.Read<ushort>(table + --row * Columns + Unsafe.Read<byte>(input + i + pos++)) ^
                                                Unsafe.Read<ushort>(table + --row * Columns + Unsafe.Read<byte>(input + i + pos++)) ^
                                                Unsafe.Read<ushort>(table + --row * Columns + Unsafe.Read<byte>(input + i + pos++)) ^
                                                Unsafe.Read<ushort>(table + --row * Columns + Unsafe.Read<byte>(input + i + pos++)) ^
                                                Unsafe.Read<ushort>(table + --row * Columns + Unsafe.Read<byte>(input + i + pos++)) ^
                                                Unsafe.Read<ushort>(table + --row * Columns + Unsafe.Read<byte>(input + i + pos++)) ^
                                                Unsafe.Read<ushort>(table + --row * Columns + Unsafe.Read<byte>(input + i + pos++)) ^
                                                Unsafe.Read<ushort>(table + --row * Columns + Unsafe.Read<byte>(input + i + pos))) & Mask);
                                i += Rows;
                                len -= Rows;
                            }
                            break;
                        }
                    }
                    while (--len >= 0)
                        AppendData(input[i++], table, ref sum);
                }
            hash = sum;
        }

        /// <inheritdoc/>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public unsafe void AppendData(byte value, ref ushort hash)
        {
            fixed (ushort* table = Table.Span)
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
                hash = (ushort)((hash >> 8 ^ Unsafe.Read<ushort>(table + (value ^ hash & 0xff))) & Mask);
            else
                hash = (ushort)((Unsafe.Read<ushort>(table + ((hash >> BitWidth - 8 ^ value) & 0xff)) ^ hash << 8) & Mask);
        }

        private static ReadOnlyMemory<ushort> CreateTable(int width, ushort poly, ushort mask, bool refIn)
        {
            var top = (ushort)(1 << width - 1);
            var mem = new ushort[Rows * Columns].AsMemory();
            var span = mem.Span;

            // Phase 1: build T[0] — the standard single-byte CRC lookup table
            for (var i = 0; i < Columns; i++)
            {
                var x = (ushort)i;
                if (refIn)
                    for (var k = 0; k < 8; k++)
                        x = (ushort)((x & 1) == 1 ? x >> 1 ^ poly : x >> 1);
                else
                {
                    x <<= width - 8;
                    for (var k = 0; k < 8; k++)
                        x = (ushort)((x & top) != 0 ? x << 1 ^ poly : x << 1);
                }
                span[i] = (ushort)(x & mask);
            }

            // Phase 2: build T[1..Rows-1] by propagating one zero-byte update per row
            for (var j = 1; j < Rows; j++)
                for (var i = 0; i < Columns; i++)
                {
                    var prev = span[(j - 1) * Columns + i];
                    span[j * Columns + i] = refIn
                        ? (ushort)((prev >> 8 ^ span[prev & 0xff]) & mask)
                        : (ushort)((prev << 8 ^ span[prev >> width - 8 & 0xff]) & mask);
                }

            return mem;
        }
    }
}
