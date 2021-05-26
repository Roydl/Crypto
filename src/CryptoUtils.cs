namespace Roydl.Crypto
{
    using System;
    using System.Collections.Generic;
    using System.Linq;

    /// <summary>Provides some basic utilities.</summary>
    public static class CryptoUtils
    {
        /// <summary>Combines the specified hash codes.</summary>
        /// <param name="hash1">The first hash code.</param>
        /// <param name="hash2">The second hash code.</param>
        public static int CombineHashCodes(int hash1, int hash2)
        {
            var hash = (uint)((hash1 << 5) | (int)((uint)hash1 >> 27));
            return ((int)hash + hash1) ^ hash2;
        }

        /// <summary>Combines the hash codes of the specified objects.</summary>
        /// <param name="obj1">The first object.</param>
        /// <param name="obj2">The second object.</param>
        public static int CombineHashCodes(object obj1, object obj2) =>
            CombineHashCodes(obj1?.GetHashCode() ?? 17011, obj2?.GetHashCode() ?? 23011);

        /// <param name="hashes">A sequence of hash codes.</param>
        /// <inheritdoc cref="CombineHashCodes(int, int)"/>
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

        /// <param name="objects">A sequence of objects.</param>
        /// <inheritdoc cref="CombineHashCodes(object, object)"/>
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

        /// <summary>Returns the specified 64-bit unsigned integer value as a sequence of bytes.</summary>
        /// <param name="value">The number to convert.</param>
        /// <param name="size">The size of the sequence. Must be between 1 and 8.</param>
        /// <param name="inverted"><see langword="true"/> to invert the byte order; otherwise, <see langword="false"/>.</param>
        /// <exception cref="ArgumentOutOfRangeException">size is less 1 or greater 8.</exception>
        /// <returns>A sequence of bytes with length of size.</returns>
        public static IEnumerable<byte> GetBytes(ulong value, int size, bool inverted)
        {
            if (size is < 1 or > 8)
                throw new ArgumentOutOfRangeException(nameof(size), size, null);
            var i = 0;
            while (inverted ? --size >= 0 : i++ < size)
                yield return (byte)((value >> (8 * (inverted ? size : i - 1))) & 0xff);
        }

        /// <summary>Returns the specified 64-bit unsigned integer value as a sequence of bytes.</summary>
        /// <remarks>The byte order is automatically reversed if <see cref="BitConverter.IsLittleEndian"/> is <see langword="true"/>.</remarks>
        /// <inheritdoc cref="GetBytes(ulong, int, bool)"/>
        public static IEnumerable<byte> GetBytes(ulong value, int size) =>
            GetBytes(value, size, BitConverter.IsLittleEndian);

        /// <summary>Returns the specified 64-bit unsigned integer value as an array of bytes.</summary>
        /// <returns>An array of bytes with length of size.</returns>
        /// <inheritdoc cref="GetBytes(ulong, int, bool)"/>
        public static byte[] GetByteArray(ulong value, int size, bool inverted) =>
            GetBytes(value, size, inverted)?.ToArray();

        /// <summary>Returns the specified 64-bit unsigned integer value as an array of bytes.</summary>
        /// <remarks>The byte order is automatically reversed if <see cref="BitConverter.IsLittleEndian"/> is <see langword="true"/>.</remarks>
        /// <inheritdoc cref="GetByteArray(ulong, int, bool)"/>
        public static byte[] GetByteArray(ulong value, int size) =>
            GetBytes(value, size)?.ToArray();
    }
}
