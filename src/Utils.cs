namespace Roydl.Crypto
{
    using System;
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
            algorithm switch
            {
                BinaryToTextEncoding.Base2 => CacheInvestor.GetDefault<Base2>(),
                BinaryToTextEncoding.Base8 => CacheInvestor.GetDefault<Base8>(),
                BinaryToTextEncoding.Base10 => CacheInvestor.GetDefault<Base10>(),
                BinaryToTextEncoding.Base16 => CacheInvestor.GetDefault<Base16>(),
                BinaryToTextEncoding.Base32 => CacheInvestor.GetDefault<Base32>(),
                BinaryToTextEncoding.Base64 => CacheInvestor.GetDefault<Base64>(),
                BinaryToTextEncoding.Base85 => CacheInvestor.GetDefault<Base85>(),
                BinaryToTextEncoding.Base91 => CacheInvestor.GetDefault<Base91>(),
                _ => throw new ArgumentOutOfRangeException(nameof(algorithm))
            };

        internal static ChecksumSample GetDefaultInstance(ChecksumAlgorithm algorithm) =>
            algorithm switch
            {
                ChecksumAlgorithm.Adler32 => CacheInvestor.GetDefault<Adler32>(),
                ChecksumAlgorithm.Crc16 => CacheInvestor.GetDefault<Crc16>(),
                ChecksumAlgorithm.Crc32 => CacheInvestor.GetDefault<Crc32>(),
                ChecksumAlgorithm.Crc64 => CacheInvestor.GetDefault<Crc64>(),
                ChecksumAlgorithm.Md5 => CacheInvestor.GetDefault<Md5>(),
                ChecksumAlgorithm.Sha1 => CacheInvestor.GetDefault<Sha1>(),
                ChecksumAlgorithm.Sha256 => CacheInvestor.GetDefault<Sha256>(),
                ChecksumAlgorithm.Sha384 => CacheInvestor.GetDefault<Sha384>(),
                ChecksumAlgorithm.Sha512 => CacheInvestor.GetDefault<Sha512>(),
                _ => throw new ArgumentOutOfRangeException(nameof(algorithm))
            };

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
