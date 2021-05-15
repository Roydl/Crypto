namespace Roydl.Crypto
{
    using System;
    using System.Collections;
    using System.Collections.Generic;
    using System.Linq;
    using System.Text;

    /// <summary>
    ///     Provides some basic utilities.
    /// </summary>
    public static class CryptoUtils
    {
        /// <summary>
        ///     Combines the specified hash codes.
        /// </summary>
        /// <param name="hash1">
        ///     The first hash code.
        /// </param>
        /// <param name="hash2">
        ///     The second hash code.
        /// </param>
        public static int CombineHashCodes(int hash1, int hash2)
        {
            var hash = (uint)((hash1 << 5) | (int)((uint)hash1 >> 27));
            return ((int)hash + hash1) ^ hash2;
        }

        /// <summary>
        ///     Combines the hash codes of the specified objects.
        /// </summary>
        /// <param name="obj1">
        ///     The first object.
        /// </param>
        /// <param name="obj2">
        ///     The second object.
        /// </param>
        public static int CombineHashCodes(object obj1, object obj2) =>
            CombineHashCodes(obj1?.GetHashCode() ?? 17011, obj2?.GetHashCode() ?? 23011);

        /// <summary>
        ///     Combines the specified hash codes.
        /// </summary>
        /// <param name="hashes">
        ///     A sequence of hash codes.
        /// </param>
        public static int CombineHashCodes(params int[] hashes)
        {
            switch (hashes?.Length)
            {
                case null:
                case 0:
                    return 0;
                case 1:
                    return hashes[0];
                case 2:
                    return CombineHashCodes(hashes[0], hashes[1]);
                default:
                    var hash = hashes[0];
                    for (var i = 1; i < hashes.Length; i++)
                        hash = CombineHashCodes(hash, hashes[i]);
                    return hash;
            }
        }

        /// <summary>
        ///     Combines the hash codes of the specified objects.
        /// </summary>
        /// <param name="objects">
        ///     A sequence of hash codes.
        /// </param>
        public static int CombineHashCodes(params object[] objects)
        {
            switch (objects?.Length)
            {
                case null:
                case 0:
                    return 0;
                case 1:
                    return CombineHashCodes(objects[0], null);
                case 2:
                    return CombineHashCodes(objects[0], objects[1]);
                default:
                    var hash = objects[0]?.GetHashCode() ?? 17011;
                    for (var i = 1; i < objects.Length; i++)
                        hash = CombineHashCodes(hash, objects[i]?.GetHashCode() ?? 23011);
                    return hash;
            }
        }

        internal static void CombineHashes(StringBuilder builder, string hash1, string hash2, bool braces)
        {
            if (braces)
                builder.Append('{');
            var first = hash1 ?? new string('0', 8);
            if (first.Length < 8)
                first = first.PadLeft(8, '0');
            if (first.Length > 8)
                first = first[..8];
            builder.Append(first);
            var second = hash2 ?? new string('0', 12);
            if (second.Length < 12)
                second = first.PadRight(12, '0');
            for (var i = 0; i < 3; i++)
            {
                builder.Append('-');
                builder.Append(second.Substring(i * 4, 4));
            }
            builder.Append('-');
            builder.Append(second[^12..]);
            if (braces)
                builder.Append('}');
        }

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

        internal static IEnumerable<byte> GetBytes(ulong value, int size, bool inverted)
        {
            var i = 0;
            size = Math.Abs(size);
            while (inverted ? --size >= 0 : i++ < size)
                yield return (byte)((value >> (8 * (inverted ? size : i - 1))) & 0xff);
        }

        internal static byte[] GetByteArray(ulong value, int bits, bool inverted) =>
            GetBytes(value, bits, inverted)?.ToArray();
    }
}
