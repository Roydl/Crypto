namespace Roydl.Crypto
{
    using System;
    using System.Collections.Generic;
    using System.Linq;

    /// <summary>Provides some basic utilities.</summary>
    public static class CryptoUtils
    {
        /// <summary>Combines the specified 32-bit signed integers.</summary>
        /// <param name="hash1">The first 32-bit signed integer.</param>
        /// <param name="hash2">The second 32-bit signed integer.</param>
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

        /// <param name="hashes">A sequence of 32-bit signed integers.</param>
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
            if (size is < 1 or > sizeof(ulong))
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

        /// <summary>Returns the specified 32-bit unsigned integer value as a sequence of bytes.</summary>
        /// <param name="value">The number to convert.</param>
        /// <param name="size">The size of the sequence. Must be between 1 and 4.</param>
        /// <param name="inverted"><see langword="true"/> to invert the byte order; otherwise, <see langword="false"/>.</param>
        /// <exception cref="ArgumentOutOfRangeException">size is less 1 or greater 4.</exception>
        /// <returns>A sequence of bytes with length of size.</returns>
        public static IEnumerable<byte> GetBytes(uint value, int size, bool inverted)
        {
            if (size is < 1 or > sizeof(uint))
                throw new ArgumentOutOfRangeException(nameof(size), size, null);
            var i = 0;
            while (inverted ? --size >= 0 : i++ < size)
                yield return (byte)((value >> (8 * (inverted ? size : i - 1))) & 0xff);
        }

        /// <summary>Returns the specified 32-bit unsigned integer value as a sequence of bytes.</summary>
        /// <remarks>The byte order is automatically reversed if <see cref="BitConverter.IsLittleEndian"/> is <see langword="true"/>.</remarks>
        /// <inheritdoc cref="GetBytes(uint, int, bool)"/>
        public static IEnumerable<byte> GetBytes(uint value, int size) =>
            GetBytes(value, size, BitConverter.IsLittleEndian);

        /// <summary>Returns the specified 32-bit unsigned integer value as an array of bytes.</summary>
        /// <returns>An array of bytes with length of size.</returns>
        /// <inheritdoc cref="GetBytes(uint, int, bool)"/>
        public static byte[] GetByteArray(uint value, int size, bool inverted) =>
            GetBytes(value, size, inverted)?.ToArray();

        /// <summary>Returns the specified 32-bit unsigned integer value as an array of bytes.</summary>
        /// <remarks>The byte order is automatically reversed if <see cref="BitConverter.IsLittleEndian"/> is <see langword="true"/>.</remarks>
        /// <inheritdoc cref="GetByteArray(uint, int, bool)"/>
        public static byte[] GetByteArray(uint value, int size) =>
            GetBytes(value, size)?.ToArray();

        /// <summary>Returns the specified 16-bit unsigned integer value as a sequence of bytes.</summary>
        /// <param name="value">The number to convert.</param>
        /// <param name="size">The size of the sequence. Must be between 1 and 2.</param>
        /// <param name="inverted"><see langword="true"/> to invert the byte order; otherwise, <see langword="false"/>.</param>
        /// <exception cref="ArgumentOutOfRangeException">size is less 1 or greater 2.</exception>
        /// <returns>A sequence of bytes with length of size.</returns>
        public static IEnumerable<byte> GetBytes(ushort value, int size, bool inverted)
        {
            if (size is < 1 or > sizeof(ushort))
                throw new ArgumentOutOfRangeException(nameof(size), size, null);
            var i = 0;
            while (inverted ? --size >= 0 : i++ < size)
                yield return (byte)((value >> (8 * (inverted ? size : i - 1))) & 0xff);
        }

        /// <summary>Returns the specified 16-bit unsigned integer value as a sequence of bytes.</summary>
        /// <remarks>The byte order is automatically reversed if <see cref="BitConverter.IsLittleEndian"/> is <see langword="true"/>.</remarks>
        /// <inheritdoc cref="GetBytes(ushort, int, bool)"/>
        public static IEnumerable<byte> GetBytes(ushort value, int size) =>
            GetBytes(value, size, BitConverter.IsLittleEndian);

        /// <summary>Returns the specified 16-bit unsigned integer value as an array of bytes.</summary>
        /// <returns>An array of bytes with length of size.</returns>
        /// <inheritdoc cref="GetBytes(ushort, int, bool)"/>
        public static byte[] GetByteArray(ushort value, int size, bool inverted) =>
            GetBytes(value, size, inverted)?.ToArray();

        /// <summary>Returns the specified 16-bit unsigned integer value as an array of bytes.</summary>
        /// <remarks>The byte order is automatically reversed if <see cref="BitConverter.IsLittleEndian"/> is <see langword="true"/>.</remarks>
        /// <inheritdoc cref="GetByteArray(ushort, int, bool)"/>
        public static byte[] GetByteArray(ushort value, int size) =>
            GetBytes(value, size)?.ToArray();

        /// <summary>Returns the specified byte sequence as 64-bit unsigned integer value.</summary>
        /// <param name="bytes">The byte sequence to convert.</param>
        /// <returns>A 64-bit unsigned integer.</returns>
        public static ulong GetUInt64(ReadOnlySpan<byte> bytes)
        {
            var value = 0uL;
            if (bytes.Length > 0)
                value = ((ulong)bytes[0] << 56) & 0xff00000000000000uL;
            if (bytes.Length > 1)
                value |= ((ulong)bytes[1] << 48) & 0xff000000000000uL;
            if (bytes.Length > 2)
                value |= ((ulong)bytes[2] << 40) & 0xff0000000000uL;
            if (bytes.Length > 3)
                value |= ((ulong)bytes[3] << 32) & 0xff00000000uL;
            if (bytes.Length > 4)
                value |= ((ulong)bytes[4] << 24) & 0xff000000uL;
            if (bytes.Length > 5)
                value |= ((ulong)bytes[5] << 16) & 0xff0000uL;
            if (bytes.Length > 6)
                value |= ((ulong)bytes[6] << 8) & 0xff00uL;
            if (bytes.Length > 7)
                value |= bytes[7] & 0xffuL;
            return value;
        }

        /// <summary>Returns the specified byte sequence as 32-bit unsigned integer value.</summary>
        /// <returns>A 32-bit unsigned integer.</returns>
        /// <inheritdoc cref="GetUInt64"/>
        public static uint GetUInt32(ReadOnlySpan<byte> bytes)
        {
            var value = 0u;
            if (bytes.Length > 0)
                value = ((uint)bytes[0] << 24) & 0xff000000u;
            if (bytes.Length > 1)
                value |= ((uint)bytes[1] << 16) & 0xff0000u;
            if (bytes.Length > 2)
                value |= ((uint)bytes[2] << 8) & 0xff00u;
            if (bytes.Length > 3)
                value |= bytes[3] & 0xffu;
            return value;
        }

        /// <summary>Returns the specified byte sequence as 16-bit unsigned integer value.</summary>
        /// <returns>A 16-bit unsigned integer.</returns>
        /// <inheritdoc cref="GetUInt64"/>
        public static ushort GetUInt16(ReadOnlySpan<byte> bytes)
        {
            var value = (ushort)0;
            if (bytes.Length > 0)
                value = (ushort)((bytes[0] << 8) & 0xff00);
            if (bytes.Length > 1)
                value |= (ushort)(bytes[1] & 0xff);
            return value;
        }
    }
}
