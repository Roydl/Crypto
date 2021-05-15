namespace Roydl.Crypto
{
    using System;
    using System.Collections;
    using System.Collections.Generic;
    using System.Linq;

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

        /// <summary>
        ///     Returns the specified 64-bit unsigned integer value as a sequence of bytes.
        /// </summary>
        /// <param name="value">
        ///     The number to convert.
        /// </param>
        /// <param name="size">
        ///     The size of the sequence. Must be between 1 and 64.
        /// </param>
        /// <param name="inverted">
        ///     <see langword="true"/> to invert the order; otherwise,
        ///     <see langword="false"/>.
        /// </param>
        /// <exception cref="ArgumentOutOfRangeException">
        ///     size is less 1 or greater 64.
        /// </exception>
        /// <returns>
        ///     A sequence of bytes with length of size.
        /// </returns>
        public static IEnumerable<byte> GetBytes(ulong value, int size, bool inverted)
        {
            if (size is < 1 or > 64)
                throw new ArgumentOutOfRangeException(nameof(size), size, null);
            var i = 0;
            while (inverted ? --size >= 0 : i++ < size)
                yield return (byte)((value >> (8 * (inverted ? size : i - 1))) & 0xff);
        }

        /// <summary>
        ///     Returns the specified 64-bit unsigned integer value as an array of bytes.
        /// </summary>
        /// <param name="value">
        ///     The number to convert.
        /// </param>
        /// <param name="size">
        ///     The size of the sequence. Must be between 1 and 64.
        /// </param>
        /// <param name="inverted">
        ///     <see langword="true"/> to invert the order; otherwise,
        ///     <see langword="false"/>.
        /// </param>
        /// <exception cref="ArgumentOutOfRangeException">
        ///     size is less 1 or greater 64.
        /// </exception>
        /// <returns>
        ///     An array of bytes with length of size.
        /// </returns>
        public static byte[] GetByteArray(ulong value, int size, bool inverted) =>
            GetBytes(value, size, inverted)?.ToArray();

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
    }
}
