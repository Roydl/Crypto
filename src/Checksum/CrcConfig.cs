namespace Roydl.Crypto.Checksum
{
    using System;
    using System.Collections.Generic;
    using System.IO;
    using System.Linq;

    internal readonly struct CrcConfig<TValue> where TValue : IConvertible
    {
        internal int Bits { get; }

        internal TValue Mask { get; }

        internal TValue Poly { get; }

        internal TValue Seed { get; }

        internal bool Swapped { get; }

        internal bool Reversed { get; }

        internal ReadOnlyMemory<TValue> Table { get; }

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

            var mask = (TValue)typeof(TValue).GetField("MaxValue")?.GetValue(null);
            var table = CreateTable(bits, poly, mask, swapped).ToArray();

            Bits = bits;
            Mask = mask;
            Poly = poly;
            Seed = seed;
            Swapped = swapped;
            Reversed = reversed;
            Table = new ReadOnlyMemory<TValue>(table, 0, table.Length);
        }

        internal void ComputeHash(Stream stream, out TValue hash)
        {
            if (stream == null)
                throw new ArgumentNullException(nameof(stream));
            hash = Seed;
            var ba = new byte[4096];
            int len;
            while ((len = stream.Read(ba, 0, ba.Length)) > 0)
            {
                for (var i = 0; i < len; i++)
                    ComputeHash(ref hash, ba[i]);
            }
            FinalizeHash(ref hash);
        }

        private void ComputeHash(ref TValue current, int value)
        {
            if (Swapped)
            {
                current = (TValue)((((dynamic)current >> 8) ^ Table.Span[(int)((uint)value ^ ((dynamic)current & (TValue)(dynamic)0xff))]) & Mask);
                return;
            }
            current = (TValue)((Table.Span[(int)((((dynamic)current >> (Bits - 8)) ^ (uint)value) & (TValue)(dynamic)0xff)] ^ ((dynamic)current << 8)) & Mask);
        }

        private void FinalizeHash(ref TValue hash)
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
