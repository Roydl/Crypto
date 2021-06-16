namespace Roydl.Crypto.Checksum
{
    using System;
    using System.IO;
    using System.Runtime.CompilerServices;
    using System.Runtime.Intrinsics.X86;
    using Internal;
    using Resources;

    /// <summary>Represents a 32-bit CRC configuration structure.</summary>
    public readonly struct CrcConfig32 : ICrcConfig<uint>
    {
        private const int Columns = 1 << 8;
        private const int Rows = 1 << 4;
        private readonly bool _hw, _hw64;

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
            _hw = Sse42.IsSupported && bitWidth == 32 && check == 0xe3069283u;
            _hw64 = _hw && Sse42.X64.IsSupported;
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
            Table = _hw ? null : CreateTable(bitWidth, poly, mask, refIn);
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
            if (_hw)
            {
                if (_hw64)
                {
                    const int size64 = sizeof(ulong);
                    ulong sum64 = sum;
                    while (len >= size64)
                    {
                        var data = CryptoUtils.GetUInt64(bytes.Slice(i, size64), BitConverter.IsLittleEndian);
                        sum64 = Sse42.X64.Crc32(sum64, data);
                        i += size64;
                        len -= size64;
                    }
                    sum = (uint)(sum64 & Mask);
                }
                const int size = sizeof(uint);
                while (len >= size)
                {
                    var data = CryptoUtils.GetUInt32(bytes.Slice(i, size), BitConverter.IsLittleEndian);
                    sum = Sse42.Crc32(sum, data);
                    i += size;
                    len -= size;
                }
                while (--len >= 0)
                    sum = Sse42.Crc32(sum, bytes[i++]);
                hash = sum;
                return;
            }
            fixed (uint* table = &Table.Span[0])
            {
                while (RefIn && len >= Rows)
                {
                    var row = Rows;
                    var pos = 0;
                    sum = (table[--row * Columns + (((sum >> 00) & 0xff) ^ bytes[i + pos++])] ^
                           table[--row * Columns + (((sum >> 08) & 0xff) ^ bytes[i + pos++])] ^
                           table[--row * Columns + (((sum >> 16) & 0xff) ^ bytes[i + pos++])] ^
                           table[--row * Columns + (((sum >> 24) & 0xff) ^ bytes[i + pos++])] ^
                           table[--row * Columns + bytes[i + pos++]] ^
                           table[--row * Columns + bytes[i + pos++]] ^
                           table[--row * Columns + bytes[i + pos++]] ^
                           table[--row * Columns + bytes[i + pos++]] ^
                           table[--row * Columns + bytes[i + pos++]] ^
                           table[--row * Columns + bytes[i + pos++]] ^
                           table[--row * Columns + bytes[i + pos++]] ^
                           table[--row * Columns + bytes[i + pos++]] ^
                           table[--row * Columns + bytes[i + pos++]] ^
                           table[--row * Columns + bytes[i + pos++]] ^
                           table[--row * Columns + bytes[i + pos++]] ^
                           table[--row * Columns + bytes[i + pos]]) & Mask;
                    i += Rows;
                    len -= Rows;
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
            if (_hw)
            {
                hash = Sse42.Crc32(hash, value);
                return;
            }
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
