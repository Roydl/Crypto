﻿namespace Roydl.Crypto.Checksum
{
    using System;
    using System.IO;
    using System.Runtime.CompilerServices;
    using System.Runtime.Intrinsics.X86;
    using Internal;
    using Resources;
#if NET5_0_OR_GREATER
    using Arm = System.Runtime.Intrinsics.Arm.Crc32;
    using Arm64 = System.Runtime.Intrinsics.Arm.Crc32.Arm64;
#endif

    /// <summary>Represents a 32-bit CRC configuration structure.</summary>
    public readonly struct CrcConfig32 : ICrcConfig<uint>
    {
        private const int Columns = 1 << 8;
        private const int Rows = 1 << 4;
        private readonly int _mode;

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
                mask = NumericHelper.CreateBitMask<uint>(bitWidth);
            BitWidth = bitWidth;
            Check = check;
            Poly = poly;
            Init = init;
            RefIn = refIn;
            RefOut = refOut;
            XorOut = xorOut;
            Mask = mask;

            _mode = bitWidth switch
            {
                32 => check switch
                {
                    0xe3069283u => 1, // `iSCSI` config, which is available for hardware mode on `ARM` and `SSE4.2 CPU`
                    0xcbf43926u => 2, // `PKZip` config, which is only available for hardware mode on `ARM` 
                    _ => 0 // Default 
                },
                _ => 0 // Software mode by default 
            };

            switch (_mode)
            {
#if NET5_0_OR_GREATER
                case > 0 when Arm.IsSupported || Arm64.IsSupported:
#endif
                case 1 when Sse42.IsSupported || Sse42.X64.IsSupported:
                    Table = null;
                    break;
                default:
                    Table = CreateTable(bitWidth, poly, mask, refIn);
                    break;
            }

            if (!skipValidation)
                CrcConfig.ThrowIfInvalid(this);
        }

        /// <inheritdoc/>
        public void ComputeHash(Stream stream, out uint hash)
        {
            if (stream == null)
                throw new ArgumentNullException(nameof(stream));
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
        public void ComputeHash(ReadOnlySpan<byte> bytes, out uint hash)
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
        public unsafe void AppendData(ReadOnlySpan<byte> bytes, int len, ref uint hash)
        {
            if (bytes.IsEmpty)
                throw new ArgumentException(ExceptionMessages.ArgumentEmpty, nameof(bytes));
            var sum = hash;
            var i = 0;
            fixed (byte* input = bytes)
            {
                const int size32 = sizeof(uint);
                const int size64 = sizeof(ulong);
                switch (_mode)
                {
                    /*
                        adding `if` or `switch` inside `while` or `for` results in
                        significant performance degradation, so we cannot simply
                        merge the loops below
                    */
#if NET5_0_OR_GREATER
                    case > 0 when Arm64.IsSupported:
                    {
                        if (_mode > 1)
                            for (; len >= size64; i += size64, len -= size64)
                                sum = Arm64.ComputeCrc32(sum, Unsafe.Read<ulong>(input + i));
                        else
                            for (; len >= size64; i += size64, len -= size64)
                                sum = Arm64.ComputeCrc32C(sum, Unsafe.Read<ulong>(input + i));
                        while (--len >= 0)
                            AppendData(input[i++], ref sum);
                        hash = sum;
                        return;
                    }
#endif
                    case 1 when Sse42.IsSupported:
                    {
                        if (Sse42.X64.IsSupported)
                        {
                            ulong sum64 = sum;
                            for (; len >= size64; i += size64, len -= size64)
                                sum64 = Sse42.X64.Crc32(sum64, Unsafe.Read<ulong>(input + i));
                            if (sum != sum64)
                                sum = (uint)(sum64 & Mask);
                        }
                        for (; len >= size32; i += size32, len -= size32)
                            sum = Sse42.Crc32(sum, Unsafe.Read<uint>(input + i));
                        while (--len >= 0)
                            AppendData(input[i++], ref sum);
                        hash = sum;
                        return;
                    }
                }
                fixed (uint* table = Table.Span)
                {
                    /*
                        replacing `i + pos++` with `i++` or replacing `--row` with
                        constants, both lead to a significant drop in performance
                    */
                    while (RefIn && len >= Rows)
                    {
                        var row = Rows;
                        var pos = 0;
                        sum = (Unsafe.Read<uint>(table + --row * Columns + (((sum >> 00) & 0xff) ^ Unsafe.Read<byte>(input + i + pos++))) ^
                               Unsafe.Read<uint>(table + --row * Columns + (((sum >> 08) & 0xff) ^ Unsafe.Read<byte>(input + i + pos++))) ^
                               Unsafe.Read<uint>(table + --row * Columns + (((sum >> 16) & 0xff) ^ Unsafe.Read<byte>(input + i + pos++))) ^
                               Unsafe.Read<uint>(table + --row * Columns + (((sum >> 24) & 0xff) ^ Unsafe.Read<byte>(input + i + pos++))) ^
                               Unsafe.Read<uint>(table + --row * Columns + Unsafe.Read<byte>(input + i + pos++)) ^
                               Unsafe.Read<uint>(table + --row * Columns + Unsafe.Read<byte>(input + i + pos++)) ^
                               Unsafe.Read<uint>(table + --row * Columns + Unsafe.Read<byte>(input + i + pos++)) ^
                               Unsafe.Read<uint>(table + --row * Columns + Unsafe.Read<byte>(input + i + pos++)) ^
                               Unsafe.Read<uint>(table + --row * Columns + Unsafe.Read<byte>(input + i + pos++)) ^
                               Unsafe.Read<uint>(table + --row * Columns + Unsafe.Read<byte>(input + i + pos++)) ^
                               Unsafe.Read<uint>(table + --row * Columns + Unsafe.Read<byte>(input + i + pos++)) ^
                               Unsafe.Read<uint>(table + --row * Columns + Unsafe.Read<byte>(input + i + pos++)) ^
                               Unsafe.Read<uint>(table + --row * Columns + Unsafe.Read<byte>(input + i + pos++)) ^
                               Unsafe.Read<uint>(table + --row * Columns + Unsafe.Read<byte>(input + i + pos++)) ^
                               Unsafe.Read<uint>(table + --row * Columns + Unsafe.Read<byte>(input + i + pos++)) ^
                               Unsafe.Read<uint>(table + --row * Columns + Unsafe.Read<byte>(input + i + pos))) & Mask;
                        i += Rows;
                        len -= Rows;
                    }
                    while (--len >= 0)
                        AppendData(input[i++], table, ref sum);
                }
            }
            hash = sum;
        }

        /// <inheritdoc/>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public unsafe void AppendData(byte value, ref uint hash)
        {
            switch (_mode)
            {
#if NET5_0_OR_GREATER
                case 2 when Arm.IsSupported:
                    hash = Arm.ComputeCrc32(hash, value);
                    return;
                case 1 when Arm.IsSupported:
                    hash = Arm.ComputeCrc32C(hash, value);
                    return;
#endif
                case 1 when Sse42.IsSupported:
                    hash = Sse42.Crc32(hash, value);
                    return;
            }
            fixed (uint* table = Table.Span)
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
        public bool IsValid(out uint current)
        {
            ComputeHash(CrcConfig.ValidationBytes, out current);
            return current == Check;
        }

        /// <inheritdoc/>
        public bool IsValid() =>
            IsValid(out _);

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private unsafe void AppendData(byte value, uint* table, ref uint hash)
        {
            if (RefIn)
                hash = ((hash >> 8) ^ Unsafe.Read<uint>(table + (value ^ (hash & 0xff)))) & Mask;
            else
                hash = (Unsafe.Read<uint>(table + (((hash >> (BitWidth - 8)) ^ value) & 0xff)) ^ (hash << 8)) & Mask;
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
