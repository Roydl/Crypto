namespace Roydl.Crypto
{
    using System;
    using System.Buffers.Binary;
    using System.Numerics;
    using Resources;

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

        /// <summary>Returns the specified <typeparamref name="TValue"/> value as a sequence of bytes.</summary>
        /// <param name="source">The <typeparamref name="TValue"/> value to convert.</param>
        /// <param name="isLittleEndian"><see langword="true"/> to order bytes as little endian; otherwise, <see langword="false"/>.</param>
        /// <exception cref="InvalidOperationException">TValue is invalid, i.e. not supported.</exception>
        /// <returns>A sequence of bytes that represents the specified value.</returns>
        public static byte[] GetByteArray<TValue>(TValue source, bool isLittleEndian) where TValue : struct, IComparable, IFormattable
        {
            byte[] bytes;
            switch (source)
            {
                case sbyte x:
                    bytes = new[] { (byte)x };
                    break;
                case byte x:
                    bytes = new[] { x };
                    break;
                case short x:
                    bytes = new byte[sizeof(short)];
                    if (isLittleEndian)
                        BinaryPrimitives.WriteInt16LittleEndian(bytes, x);
                    else
                        BinaryPrimitives.WriteInt16BigEndian(bytes, x);
                    break;
                case ushort x:
                    bytes = new byte[sizeof(ushort)];
                    if (isLittleEndian)
                        BinaryPrimitives.WriteUInt16LittleEndian(bytes, x);
                    else
                        BinaryPrimitives.WriteUInt16BigEndian(bytes, x);
                    break;
                case int x:
                    bytes = new byte[sizeof(int)];
                    if (isLittleEndian)
                        BinaryPrimitives.WriteInt32LittleEndian(bytes, x);
                    else
                        BinaryPrimitives.WriteInt32BigEndian(bytes, x);
                    break;
                case uint x:
                    bytes = new byte[sizeof(uint)];
                    if (isLittleEndian)
                        BinaryPrimitives.WriteUInt32LittleEndian(bytes, x);
                    else
                        BinaryPrimitives.WriteUInt32BigEndian(bytes, x);
                    break;
                case long x:
                    bytes = new byte[sizeof(long)];
                    if (isLittleEndian)
                        BinaryPrimitives.WriteInt64LittleEndian(bytes, x);
                    else
                        BinaryPrimitives.WriteInt64BigEndian(bytes, x);
                    break;
                case ulong x:
                    bytes = new byte[sizeof(ulong)];
                    if (isLittleEndian)
                        BinaryPrimitives.WriteUInt64LittleEndian(bytes, x);
                    else
                        BinaryPrimitives.WriteUInt64BigEndian(bytes, x);
                    break;
#if NET5_0_OR_GREATER
                case float x:
                    bytes = new byte[sizeof(float)];
                    if (isLittleEndian)
                        BinaryPrimitives.WriteSingleLittleEndian(bytes, x);
                    else
                        BinaryPrimitives.WriteSingleBigEndian(bytes, x);
                    break;
                case double x:
                    bytes = new byte[sizeof(double)];
                    if (isLittleEndian)
                        BinaryPrimitives.WriteDoubleLittleEndian(bytes, x);
                    else
                        BinaryPrimitives.WriteDoubleBigEndian(bytes, x);
                    break;
#endif
                case BigInteger x:
                    bytes = x.ToByteArray(true, !isLittleEndian);
                    break;
                default:
                    throw new InvalidOperationException(ExceptionMessages.InvalidOperationUnsupportedType);
            }
            return bytes;
        }

        /// <summary>Returns the specified sequence of bytes as 64-bit unsigned integer value.</summary>
        /// <param name="source">The sequence of bytes to convert.</param>
        /// <param name="isLittleEndian"><see langword="true"/> to order bytes as little endian; otherwise, <see langword="false"/>.</param>
        /// <exception cref="ArgumentOutOfRangeException">source is too small.</exception>
        /// <returns>A 64-bit unsigned integer representing the specified sequence of bytes.</returns>
        public static ulong GetUInt64(ReadOnlySpan<byte> source, bool isLittleEndian) =>
            isLittleEndian ? BinaryPrimitives.ReadUInt64LittleEndian(source) : BinaryPrimitives.ReadUInt64BigEndian(source);

        /// <summary>Returns the specified sequence of bytes as 32-bit unsigned integer value.</summary>
        /// <returns>A 32-bit unsigned integer representing the specified sequence of bytes.</returns>
        /// <inheritdoc cref="GetUInt64"/>
        public static uint GetUInt32(ReadOnlySpan<byte> source, bool isLittleEndian) =>
            isLittleEndian ? BinaryPrimitives.ReadUInt32LittleEndian(source) : BinaryPrimitives.ReadUInt32BigEndian(source);

        /// <summary>Returns the specified sequence of bytes as 16-bit unsigned integer value.</summary>
        /// <returns>A 16-bit unsigned integer representing the specified sequence of bytes.</returns>
        /// <inheritdoc cref="GetUInt64"/>
        public static ushort GetUInt16(ReadOnlySpan<byte> source, bool isLittleEndian) =>
            isLittleEndian ? BinaryPrimitives.ReadUInt16LittleEndian(source) : BinaryPrimitives.ReadUInt16BigEndian(source);
    }
}
