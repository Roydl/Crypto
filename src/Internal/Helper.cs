namespace Roydl.Crypto.Internal
{
    using System;
    using System.Collections;
    using System.Diagnostics.CodeAnalysis;
    using System.Globalization;
    using System.IO;
    using System.Numerics;

    internal static class Helper
    {
        internal static void DestroyElement<TElement>(ref TElement element) where TElement : class
        {
            if (element == null)
                return;
            var isCollection = false;
            switch (element)
            {
                case ICollection:
                    isCollection = element is not Array;
                    break;
                case IDisposable disposable:
                    disposable.Dispose();
                    break;
            }
            var generation = GC.GetGeneration(element);
            element = null;
            GC.Collect(generation, GCCollectionMode.Forced);
            if (isCollection)
                GC.Collect();
        }

        internal static int GetBufferSize(this Stream stream)
        {
            const int kb128 = 0x20000;
            const int kb64 = 0x10000;
            const int kb32 = 0x8000;
            const int kb16 = 0x4000;
            const int kb8 = 0x2000;
            const int kb4 = 0x1000;
            return (int)Math.Floor((stream?.Length ?? 0) / 1.5d) switch
            {
                > kb128 => kb128,
                > kb64 => kb64,
                > kb32 => kb32,
                > kb16 => kb16,
                > kb8 => kb8,
                _ => kb4
            };
        }

        internal static string ToHexStr<T>(this T num, int padding, bool prefix) where T : struct, IComparable, IFormattable
        {
            var str = num.ToString("x2", null);
            if (padding > 2)
                str = str.PadLeft(padding, '0');
            if (prefix)
                str = "0x" + str;
            return str;
        }

        internal static BigInteger ToBigInt([AllowNull] this string hex)
        {
            if (string.IsNullOrWhiteSpace(hex))
                return BigInteger.Zero;
            return BigInteger.TryParse(hex, NumberStyles.AllowHexSpecifier, null, out var result) ? result : BigInteger.Zero;
        }
    }
}
