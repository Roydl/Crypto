namespace Roydl.Crypto.Checksum
{
    using System;
    using System.IO;
    using Internal;
    using Resources;

    /// <summary>Represents a 16-bit CRC configuration structure.</summary>
    public readonly struct CrcConfig16 : ICrcConfig<ushort>
    {
        private const int Columns = 1 << 8;
        private const int Rows = 1 << 3;

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
        public unsafe void ComputeHash(Stream stream, out ushort hash)
        {
            if (stream == null)
                throw new ArgumentNullException(nameof(stream));
            fixed (ushort* table = Table.Span)
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

                            sum = (ushort)(
                                table[5 * Columns + buffer[i + 2]] ^
                                table[4 * Columns + buffer[i + 3]] ^
                                table[3 * Columns + buffer[i + 4]] ^
                                table[2 * Columns + buffer[i + 5]] ^
                                table[1 * Columns + buffer[i + 6]] ^
                                table[0 * Columns + buffer[i + 7]]
                            );

                            sum ^= (ushort)(
                                table[7 * Columns + (((x >> 0) & 0xff) ^ buffer[i + 0])] ^
                                table[6 * Columns + (((x >> 8) & 0xff) ^ buffer[i + 1])]
                            );

                            i += Rows;
                            len -= Rows;
                            sum &= Mask;
                        }
                        while (--len >= 0)
                        {
                            var value = buffer[i++];
                            if (RefIn)
                                sum = (ushort)(((sum >> 8) ^ table[value ^ (sum & 0xff)]) & Mask);
                            else
                                sum = (ushort)((table[((sum >> (Bits - 8)) ^ value) & 0xff] ^ (sum << 8)) & Mask);
                        }
                    }
                }
                hash = sum;
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
            if (!RefIn && RefOut)
                hash = hash.ReverseBits();
            else if (RefIn ^ RefOut)
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
                        x <<= bits - 8;
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
