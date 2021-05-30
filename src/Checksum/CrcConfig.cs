namespace Roydl.Crypto.Checksum
{
    using System;
    using System.IO;
    using System.Numerics;
    using System.Runtime.InteropServices;
    using Internal;
    using Resources;

    /// <summary>Represents a CRC configuration structure.</summary>
    /// <typeparam name="TValue">The integral type of the hash code. Must be <see cref="byte"/>, <see cref="ushort"/>, <see cref="uint"/>, <see cref="ulong"/>, or <see cref="BigInteger"/>.</typeparam>
    public readonly struct CrcConfig<TValue> where TValue : IFormattable
    {
        /// <summary>Gets the hash size in bits.</summary>
        public int Bits { get; }

        /// <summary>Gets the mask of <typeparamref name="TValue"/>.</summary>
        public TValue Mask { get; }

        /// <summary>Gets the polynomial used to generate the CRC hash table.</summary>
        /// <remarks>Used to create the <see cref="Table"/> once.</remarks>
        public TValue Poly { get; }

        /// <summary>Gets the seed from which the CRC register should be initialized at beginning of the calculation.</summary>
        /// <remarks>Only automatically used in <see cref="ComputeHash(Stream, out TValue)"/>.</remarks>
        public TValue Init { get; }

        /// <summary>Gets the value that determines whether the input bytes are processed in big-endian bit order for the calculation.</summary>
        /// <remarks>Used in <see cref="ComputeHash(byte, ref TValue)"/>, which is also called by <see cref="ComputeHash(Stream, out TValue)"/>.</remarks>
        public bool RefIn { get; }

        /// <summary>Gets the value that determines whether the bits of the calculated hash code are reversed.</summary>
        /// <remarks>Used in <see cref="FinalizeHash(ref TValue)"/>.</remarks>
        public bool RefOut { get; }

        /// <summary>The value to xor with the calculated hash code.</summary>
        /// <remarks>Used in <see cref="FinalizeHash(ref TValue)"/>.</remarks>
        public TValue XorOut { get; }

        /// <summary>Gets the generated hash table of the configured CRC algorithm.</summary>
        /// <remarks>For more information, see <see cref="Poly">Poly</see>.</remarks>
        public ReadOnlyMemory<TValue> Table { get; }

        /// <summary>Creates a new configuration of the <see cref="CrcConfig{TValue}"/> struct.</summary>
        /// <param name="bits">The size in bits.</param>
        /// <param name="poly">The polynomial used to generate CRC hash table.</param>
        /// <param name="init">The seed from which the CRC register should be initialized at beginning of the calculation.</param>
        /// <param name="refIn"><see langword="true"/> to process the input bytes in big-endian bit order for the calculation; otherwise, <see langword="false"/>.</param>
        /// <param name="refOut"><see langword="true"/> to process the final output in big-endian bit order; otherwise, <see langword="false"/>.</param>
        /// <param name="xorOut">The value to xor with the final output.</param>
        /// <exception cref="ArgumentOutOfRangeException">bits are less than 8 or greater than 82.</exception>
        /// <exception cref="ArgumentException">bits are larger than the size of the TValue type allows.</exception>
        /// <exception cref="InvalidOperationException">TValue type is invalid, i.e. not supported</exception>
        public CrcConfig(int bits, TValue poly, TValue init = default, bool refIn = false, bool refOut = false, TValue xorOut = default)
        {
            if (bits is < 8 or > 82)
                throw new ArgumentOutOfRangeException(nameof(bits));
            switch (poly)
            {
                case byte:
                case ushort:
                case uint:
                case ulong:
                case BigInteger:
                    if (Marshal.SizeOf(default(TValue)) < (int)MathF.Floor(bits / 8f))
                        throw new ArgumentException(ExceptionMessages.BitsLargerThanType);
                    break;
                default:
                    throw new InvalidOperationException(ExceptionMessages.TypeInvalid);
            }
            var mask = CreateMask<TValue>(bits);
            Bits = bits;
            Mask = mask;
            Poly = poly;
            Init = init;
            RefIn = refIn;
            RefOut = refOut;
            XorOut = xorOut;
            Table = CreateTable(bits, poly, mask, refIn);
        }

        /// <summary>Computes the hash of stream data using the configured CRC algorithm.</summary>
        /// <param name="stream">The stream with the data to encrypt.</param>
        /// <param name="hash">The fully computed hash code.</param>
        /// <exception cref="ArgumentNullException">stream is null.</exception>
        /// <remarks>For more information, see <see cref="Init">Init</see>, <see cref="RefIn">RefIn</see>, <see cref="RefOut">RefOut</see> and <see cref="XorOut">XorOut</see>.</remarks>
        public void ComputeHash(Stream stream, out TValue hash)
        {
            if (stream == null)
                throw new ArgumentNullException(nameof(stream));
            hash = Init;
            var span = new byte[Helper.GetBufferSize(stream)].AsSpan();
            int len;
            while ((len = stream.Read(span)) > 0)
            {
                for (var i = 0; i < len; i++)
                    ComputeHash(span[i], ref hash);
            }
            FinalizeHash(ref hash);
        }

        /// <summary>Computes the hash of the byte value using the CRC algorithm.</summary>
        /// <param name="value">The byte value to encrypt.</param>
        /// <param name="hash">The hash code to be computed or its computation that will be continued.</param>
        /// <remarks>For more information, see <see cref="RefIn">RefIn</see>.</remarks>
        public void ComputeHash(byte value, ref TValue hash)
        {
            var byteMask = (TValue)(dynamic)0xff;
            var current = (dynamic)hash;
            var table = Table.Span;
            if (RefIn)
            {
                hash = (TValue)(((current >> 8) ^ table[(int)(value ^ (current & byteMask))]) & Mask);
                return;
            }
            hash = (TValue)((table[(int)(((current >> (Bits - 8)) ^ value) & byteMask)] ^ (current << 8)) & Mask);
        }

        /// <summary>Finalizes the computed hash code.</summary>
        /// <param name="hash">The computed hash code to be finalized.</param>
        /// <remarks>For more information, see <see cref="RefOut">RefOut</see> and <see cref="XorOut">XorOut</see>.</remarks>
        public void FinalizeHash(ref TValue hash)
        {
            if (RefIn ^ RefOut)
                hash = (TValue)~(dynamic)hash;
            hash ^= (dynamic)XorOut;
        }

        private static T CreateMask<T>(int bits)
        {
            var byteMask = (dynamic)(T)(dynamic)0xff;
            var mask = (T)byteMask;
            var size = (int)MathF.Ceiling(bits / 8f);
            for (var i = 1; i < size; i++)
                mask ^= byteMask << (8 * i);
            return mask;
        }

        private static ReadOnlyMemory<T> CreateTable<T>(int bits, T poly, T mask, bool refIn)
        {
            var top = (dynamic)(T)(dynamic)1 << (bits - 1);
            var mem = new T[1 << 8].AsMemory();
            var span = mem.Span;
            for (var i = 0; i < span.Length; i++)
            {
                var x = (dynamic)(T)(dynamic)i;
                if (refIn)
                {
                    for (var k = 0; k < 8; k++)
                        x = (T)((x & 1) == 1 ? (x >> 1) ^ poly : x >> 1);
                    span[i] = (T)(x & mask);
                    continue;
                }
                x <<= bits - 8;
                for (var j = 0; j < 8; j++)
                    x = (T)((x & top) != 0 ? (x << 1) ^ poly : x << 1);
                span[i] = (T)(x & mask);
            }
            return mem;
        }
    }
}
