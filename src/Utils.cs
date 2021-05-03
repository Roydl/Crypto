namespace Roydl.Crypto
{
    using System;
    using System.Collections.Generic;
    using System.Collections.ObjectModel;
    using System.Text;
    using System.Threading;
    using AbstractSamples;
    using BinaryToText;
    using Checksum;

    /// <summary>
    ///     Provides some basic utilities.
    /// </summary>
    public static class Utils
    {
        private static volatile Encoding _utf8NoBom;

        private static readonly ReadOnlyDictionary<BinaryToTextEncoding, Lazy<BinaryToTextSample>> LazyBinaryToTextInstances =
            new(new Dictionary<BinaryToTextEncoding, Lazy<BinaryToTextSample>>
            {
                { BinaryToTextEncoding.Radix2, new Lazy<BinaryToTextSample>(() => new Radix2(), LazyThreadSafetyMode.ExecutionAndPublication) },
                { BinaryToTextEncoding.Radix8, new Lazy<BinaryToTextSample>(() => new Radix8(), LazyThreadSafetyMode.ExecutionAndPublication) },
                { BinaryToTextEncoding.RadixA, new Lazy<BinaryToTextSample>(() => new RadixA(), LazyThreadSafetyMode.ExecutionAndPublication) },
                { BinaryToTextEncoding.RadixF, new Lazy<BinaryToTextSample>(() => new RadixF(), LazyThreadSafetyMode.ExecutionAndPublication) },
                { BinaryToTextEncoding.Base32, new Lazy<BinaryToTextSample>(() => new Base32(), LazyThreadSafetyMode.ExecutionAndPublication) },
                { BinaryToTextEncoding.Base64, new Lazy<BinaryToTextSample>(() => new Base64(), LazyThreadSafetyMode.ExecutionAndPublication) },
                { BinaryToTextEncoding.Base85, new Lazy<BinaryToTextSample>(() => new Base85(), LazyThreadSafetyMode.ExecutionAndPublication) },
                { BinaryToTextEncoding.Base91, new Lazy<BinaryToTextSample>(() => new Base91(), LazyThreadSafetyMode.ExecutionAndPublication) }
            });

        private static readonly ReadOnlyDictionary<ChecksumAlgorithm, Lazy<ChecksumSample>> LazyChecksumInstances =
            new(new Dictionary<ChecksumAlgorithm, Lazy<ChecksumSample>>
            {
                { ChecksumAlgorithm.Adler32, new Lazy<ChecksumSample>(() => new Adler32(), LazyThreadSafetyMode.ExecutionAndPublication) },
                { ChecksumAlgorithm.Crc16, new Lazy<ChecksumSample>(() => new Crc16(), LazyThreadSafetyMode.ExecutionAndPublication) },
                { ChecksumAlgorithm.Crc32, new Lazy<ChecksumSample>(() => new Crc32(), LazyThreadSafetyMode.ExecutionAndPublication) },
                { ChecksumAlgorithm.Crc64, new Lazy<ChecksumSample>(() => new Crc64(), LazyThreadSafetyMode.ExecutionAndPublication) },
                { ChecksumAlgorithm.Md5, new Lazy<ChecksumSample>(() => new Md5(), LazyThreadSafetyMode.ExecutionAndPublication) },
                { ChecksumAlgorithm.Sha1, new Lazy<ChecksumSample>(() => new Sha1(), LazyThreadSafetyMode.ExecutionAndPublication) },
                { ChecksumAlgorithm.Sha256, new Lazy<ChecksumSample>(() => new Sha256(), LazyThreadSafetyMode.ExecutionAndPublication) },
                { ChecksumAlgorithm.Sha384, new Lazy<ChecksumSample>(() => new Sha384(), LazyThreadSafetyMode.ExecutionAndPublication) },
                { ChecksumAlgorithm.Sha512, new Lazy<ChecksumSample>(() => new Sha512(), LazyThreadSafetyMode.ExecutionAndPublication) },
            });

        internal static Encoding Utf8NoBom
        {
            get
            {
                if (_utf8NoBom != null)
                    return _utf8NoBom;
                var encoding = new UTF8Encoding(false);
                Interlocked.CompareExchange(ref _utf8NoBom, encoding, null);
                return _utf8NoBom;
            }
        }

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
        /// <param name="hash1">
        ///     The first hash code.
        /// </param>
        /// <param name="hash2">
        ///     The second hash code.
        /// </param>
        /// <param name="hash3">
        ///     The third hash code.
        /// </param>
        public static int CombineHashCodes(int hash1, int hash2, int hash3) =>
            CombineHashCodes(CombineHashCodes(hash1, hash2), hash3);

        /// <summary>
        ///     Combines the hash codes of the specified objects.
        /// </summary>
        /// <param name="obj1">
        ///     The first object.
        /// </param>
        /// <param name="obj2">
        ///     The second object.
        /// </param>
        /// <param name="obj3">
        ///     The third object.
        /// </param>
        public static int CombineHashCodes(object obj1, object obj2, object obj3) =>
            CombineHashCodes(CombineHashCodes(obj1, obj2), obj3);

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
                case 3:
                    return CombineHashCodes(hashes[0], hashes[1], hashes[2]);
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
                case 3:
                    return CombineHashCodes(objects[0], objects[1], objects[2]);
                default:
                    var hash = objects[0]?.GetHashCode() ?? 17011;
                    for (var i = 1; i < objects.Length; i++)
                        hash = CombineHashCodes(hash, objects[i]?.GetHashCode() ?? 23011);
                    return hash;
            }
        }

        internal static BinaryToTextSample GetDefaultInstance(BinaryToTextEncoding algorithm) =>
            LazyBinaryToTextInstances.TryGetValue(algorithm, out var item) ? item.Value : throw new ArgumentOutOfRangeException(nameof(algorithm));

        internal static ChecksumSample GetDefaultInstance(ChecksumAlgorithm algorithm) =>
            LazyChecksumInstances.TryGetValue(algorithm, out var item) ? item.Value : throw new ArgumentOutOfRangeException(nameof(algorithm));

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
    }
}
