namespace Roydl.Crypto
{
    using System;
    using System.Collections.Generic;
    using System.IO;
    using System.Linq;
    using System.Text;
    using System.Text.Json;
    using System.Threading;
    using Checksum;

    /// <summary>
    ///     Specifies enumerated constants used to define an algorithm for encrypting
    ///     data.
    /// </summary>
    public enum ChecksumAlgo
    {
        /// <summary>
        ///     Adler-32.
        /// </summary>
        Adler32,

        /// <summary>
        ///     CRC-16 (Cyclic Redundancy Check).
        /// </summary>
        Crc16,

        /// <summary>
        ///     CRC-32 (Cyclic Redundancy Check).
        /// </summary>
        Crc32,

        /// <summary>
        ///     CRC-64 (Cyclic Redundancy Check).
        /// </summary>
        Crc64,

        /// <summary>
        ///     MD5 (Message-Digest 5).
        /// </summary>
        Md5,

        /// <summary>
        ///     SHA-1 (Secure Hash Algorithm 1).
        /// </summary>
        Sha1,

        /// <summary>
        ///     SHA-256 (Secure Hash Algorithm 2).
        /// </summary>
        Sha256,

        /// <summary>
        ///     SHA-384 (Secure Hash Algorithm 2).
        /// </summary>
        Sha384,

        /// <summary>
        ///     SHA-512 (Secure Hash Algorithm 2).
        /// </summary>
        Sha512
    }

    /// <summary>
    ///     Provides extension methods for data encryption and decryption.
    /// </summary>
    public static class CryptoExtensions
    {
        private static volatile IChecksumAlgorithm[] _cachedInstances;

        /// <summary>
        ///     Encrypts this <typeparamref name="TSource"/> object with the specified
        ///     <see cref="ChecksumAlgo"/> and combines both hashes into a unique GUID.
        /// </summary>
        /// <typeparam name="TSource">
        ///     The type of source.
        /// </typeparam>
        /// <param name="source">
        ///     The object to encrypt.
        /// </param>
        /// <param name="braces">
        ///     <see langword="true"/> to place the GUID between braces; otherwise,
        ///     <see langword="false"/>.
        /// </param>
        /// <param name="algorithm1">
        ///     The first algorithm to use.
        /// </param>
        /// <param name="algorithm2">
        ///     The second algorithm to use.
        /// </param>
        /// <returns>
        ///     A string that contains the results of encrypting the specified object by
        ///     the specified algorithms.
        /// </returns>
        public static string GetGuid<TSource>(this TSource source, bool braces = false, ChecksumAlgo algorithm1 = ChecksumAlgo.Crc32, ChecksumAlgo algorithm2 = ChecksumAlgo.Sha256)
        {
            var sb = new StringBuilder(braces ? 38 : 36);
            if (braces)
                sb.Append('{');
            var pos = (source as Stream)?.Position ?? -1L;
            var first = source?.Encrypt(algorithm1) ?? new string('0', 8);
            if (first.Length < 8)
                first = first.PadLeft(8, '0');
            if (first.Length > 8)
                first = first[..8];
            sb.Append(first);
            if (pos >= 0L && source is Stream stream)
                stream.Position = pos;
            var second = source?.Encrypt(algorithm2) ?? new string('0', 12);
            if (second.Length < 12)
                second = second.PadRight(12, '0');
            for (var i = 0; i < 3; i++)
            {
                sb.Append('-');
                sb.Append(second.Substring(i * 4, 4));
            }
            sb.Append('-');
            sb.Append(second[^12..]);
            if (braces)
                sb.Append('}');
            var s = sb.ToString();
            sb.Clear();
            return s;
        }

        /// <summary>
        ///     Encrypts this <typeparamref name="TSource"/> object with the
        ///     <see cref="ChecksumAlgo.Crc32"/> algorithm.
        /// </summary>
        /// <typeparam name="TSource">
        ///     The type of source.
        /// </typeparam>
        /// <param name="source">
        ///     The object to encrypt.
        /// </param>
        /// <param name="algorithm">
        ///     The algorithm to use.
        /// </param>
        /// <exception cref="ArgumentNullException">
        ///     source is null.
        /// </exception>
        /// <returns>
        ///     A 64-bit unsigned that contains the result of encrypting the specified
        ///     object by the specified algorithm.
        /// </returns>
        public static ulong EncryptRaw<TSource>(this TSource source, ChecksumAlgo algorithm = ChecksumAlgo.Sha256)
        {
            InternalGenericEncrypt(source, algorithm, out var instance);
            return instance.HashNumber;
        }

        /// <summary>
        ///     Encrypts this <typeparamref name="TSource"/> object with the specified
        ///     algorithm.
        /// </summary>
        /// <typeparam name="TSource">
        ///     The type of source.
        /// </typeparam>
        /// <param name="source">
        ///     The object to encrypt.
        /// </param>
        /// <param name="algorithm">
        ///     The algorithm to use.
        /// </param>
        /// <exception cref="ArgumentNullException">
        ///     source is null.
        /// </exception>
        /// <returns>
        ///     A string that contains the result of encrypting the specified object by the
        ///     specified algorithm.
        /// </returns>
        public static string Encrypt<TSource>(this TSource source, ChecksumAlgo algorithm = ChecksumAlgo.Sha256)
        {
            InternalGenericEncrypt(source, algorithm, out var instance);
            return instance.Hash;
        }

        /// <summary>
        ///     Encrypts this file with the specified algorithm.
        /// </summary>
        /// <param name="path">
        ///     The full path of the file to encrypt.
        /// </param>
        /// <param name="algorithm">
        ///     The algorithm to use.
        /// </param>
        /// <returns>
        ///     A string that contains the result of encrypting the specified file by the
        ///     specified algorithm.
        /// </returns>
        /// <inheritdoc cref="IChecksumAlgorithm.EncryptFile(string)"/>
        public static string EncryptFile(this string path, ChecksumAlgo algorithm = ChecksumAlgo.Sha256)
        {
            var instance = algorithm.GetDefaultInstance();
            instance.EncryptFile(path);
            return instance.Hash;
        }

        /// <summary>
        ///     Retrieves a cached instance of the specified algorithm.
        /// </summary>
        /// <param name="algorithm">
        ///     The algorithm to use.
        /// </param>
        /// <returns>
        ///     A cached instance of the specified algorithm.
        /// </returns>
        public static IChecksumAlgorithm GetDefaultInstance(this ChecksumAlgo algorithm)
        {
            var i = (int)algorithm;
            while (_cachedInstances == null)
                Interlocked.CompareExchange(ref _cachedInstances, new IChecksumAlgorithm[Enum.GetValues(typeof(ChecksumAlgo)).Length], null);
            while (_cachedInstances[i] == null)
                Interlocked.CompareExchange(ref _cachedInstances[i], algorithm switch
                {
                    ChecksumAlgo.Adler32 => new Adler32(),
                    ChecksumAlgo.Crc16 => new Crc16(),
                    ChecksumAlgo.Crc32 => new Crc32(),
                    ChecksumAlgo.Crc64 => new Crc64(),
                    ChecksumAlgo.Md5 => new Md5(),
                    ChecksumAlgo.Sha1 => new Sha1(),
                    ChecksumAlgo.Sha256 => new Sha256(),
                    ChecksumAlgo.Sha384 => new Sha384(),
                    ChecksumAlgo.Sha512 => new Sha512(),
                    _ => throw new ArgumentOutOfRangeException(nameof(algorithm), algorithm, null)
                }, null);
            return _cachedInstances[i];
        }

        private static void InternalGenericEncrypt<TSource>(TSource source, ChecksumAlgo algorithm, out IChecksumAlgorithm instance)
        {
            if (source == null)
                throw new ArgumentNullException(nameof(source));
            instance = algorithm.GetDefaultInstance();
            switch (source)
            {
                case Stream stream:
                    instance.Encrypt(stream);
                    return;
                case IEnumerable<byte> bytes:
                    instance.Encrypt(bytes as byte[] ?? bytes.ToArray());
                    return;
                case IEnumerable<char> chars:
                    instance.Encrypt(chars as string ?? new string(chars.ToArray()));
                    return;
            }
            using var ms = new MemoryStream();
            using var bw = new Utf8JsonWriter(ms, new JsonWriterOptions { SkipValidation = true });
            JsonSerializer.Serialize(bw, source);
            ms.Position = 0L;
            instance.Encrypt(ms);
        }
    }
}
