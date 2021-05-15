﻿namespace Roydl.Crypto.Checksum
{
    using System;
    using System.Collections.Generic;
    using System.IO;
    using System.Linq;

    /// <summary>
    ///     Represents a CRC configuration structure.
    /// </summary>
    /// <typeparam name="TValue">
    ///     The integral type of the hash code.
    /// </typeparam>
    public readonly struct CrcConfig<TValue> where TValue : IConvertible
    {
        /// <summary>
        ///     Gets the hash size in bits.
        /// </summary>
        public int Bits { get; }

        /// <summary>
        ///     Gets the mask of <typeparamref name="TValue"/>.
        /// </summary>
        public TValue Mask { get; }

        /// <summary>
        ///     Gets the polynomial used to generate the CRC hash table once.
        /// </summary>
        public TValue Poly { get; }

        /// <summary>
        ///     Gets the seed from which to start the calculation.
        ///     <para>
        ///         Is only used by default in
        ///         <see cref="ComputeHash(Stream, out TValue)"/>.
        ///     </para>
        /// </summary>
        public TValue Seed { get; }

        /// <summary>
        ///     Gets the value that determines whether the calculation is swapped.
        /// </summary>
        public bool Swapped { get; }

        /// <summary>
        ///     Gets the value that determines whether the bits of the calculated hash code
        ///     are reversed.
        /// </summary>
        public bool Reversed { get; }

        /// <summary>
        ///     Gets the generated hash table of the configured CRC algorithm.
        /// </summary>
        public ReadOnlyMemory<TValue> Table { get; }

        /// <summary>
        ///     Creates a new configuration of the <see cref="CrcConfig{TValue}"/> struct.
        /// </summary>
        /// <param name="bits">
        ///     The size in bits.
        /// </param>
        /// <param name="poly">
        ///     The polynomial used to generate CRC hash table.
        /// </param>
        /// <param name="seed">
        ///     The seed from which to start the calculation.
        /// </param>
        /// <param name="swapped">
        ///     <see langword="true"/> to swap the calculation; otherwise,
        ///     <see langword="false"/>.
        /// </param>
        /// <param name="reversed">
        ///     <see langword="true"/> to reverse the bits of the final hash code;
        ///     otherwise, <see langword="false"/>.
        /// </param>
        /// <exception cref="ArgumentOutOfRangeException">
        ///     bits is less than 8 or greater than 64.
        /// </exception>
        /// <exception cref="InvalidOperationException">
        ///     TValue type is invalid.
        /// </exception>
        public CrcConfig(int bits, TValue poly, TValue seed, bool swapped, bool reversed)
        {
            var type = typeof(TValue);
            switch (Type.GetTypeCode(type))
            {
                case TypeCode.Int16:
                case TypeCode.UInt16:
                case TypeCode.Int32:
                case TypeCode.UInt32:
                case TypeCode.Int64:
                case TypeCode.UInt64:
                    break;
                default:
                    throw new InvalidOperationException();
            }
            if (bits is < 8 or > 64)
                throw new ArgumentOutOfRangeException(nameof(bits));

            var mask = (TValue)typeof(TValue).GetField(nameof(int.MaxValue))?.GetValue(null);
            var table = CreateTable(bits, poly, mask, swapped).ToArray();

            Bits = bits;
            Mask = mask;
            Poly = poly;
            Seed = seed;
            Swapped = swapped;
            Reversed = reversed;
            Table = new ReadOnlyMemory<TValue>(table, 0, table.Length);
        }

        /// <summary>
        ///     Computes the hash of stream data using the configured CRC algorithm.
        /// </summary>
        /// <param name="stream">
        ///     The stream with the data to encrypt.
        /// </param>
        /// <param name="hash">
        ///     The fully computed hash code.
        /// </param>
        public void ComputeHash(Stream stream, out TValue hash)
        {
            if (stream == null)
                throw new ArgumentNullException(nameof(stream));
            hash = Seed;
            var ba = new byte[4096];
            int len;
            while ((len = stream.Read(ba, 0, ba.Length)) > 0)
            {
                for (var i = 0; i < len; i++)
                    ComputeHash(ba[i], ref hash);
            }
            FinalizeHash(ref hash);
        }

        /// <summary>
        ///     Computes the hash of the byte value using the CRC algorithm.
        ///     <para>
        ///         <see cref="Seed"/> is not used here.
        ///     </para>
        /// </summary>
        /// <param name="value">
        ///     The byte value to encrypt.
        /// </param>
        /// <param name="hash">
        ///     The hash code to be computed or its computation that will be continued.
        /// </param>
        public void ComputeHash(byte value, ref TValue hash)
        {
            if (Swapped)
            {
                hash = (TValue)((((dynamic)hash >> 8) ^ Table.Span[(int)(value ^ ((dynamic)hash & (TValue)(dynamic)0xff))]) & Mask);
                return;
            }
            hash = (TValue)((Table.Span[(int)((((dynamic)hash >> (Bits - 8)) ^ value) & (TValue)(dynamic)0xff)] ^ ((dynamic)hash << 8)) & Mask);
        }

        /// <summary>
        ///     Finalizes the computed hash code.
        /// </summary>
        /// <param name="hash">
        ///     The computed hash code to be finalized.
        /// </param>
        public void FinalizeHash(ref TValue hash)
        {
            if (Reversed)
                hash = (TValue)~(dynamic)hash;
        }

        private static IEnumerable<T> CreateTable<T>(int bits, T poly, T mask, bool swapped)
        {
            for (var i = 0; i < 256; i++)
            {
                var x = (dynamic)(T)(dynamic)i;
                if (swapped)
                {
                    for (var k = 0; k < 8; k++)
                        x = (T)((x & 1) == 1 ? (x >> 1) ^ poly : x >> 1);
                    yield return (T)(x & mask);
                    continue;
                }
                var top = (dynamic)(T)(dynamic)1 << (bits - 1);
                x <<= bits - 8;
                for (var j = 0; j < 8; j++)
                    x = (T)((x & top) != 0 ? (x << 1) ^ poly : x << 1);
                yield return (T)(x & mask);
            }
        }
    }
}
