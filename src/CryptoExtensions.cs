namespace Roydl.Crypto
{
    using System;
    using System.Collections.Generic;
    using System.Diagnostics.CodeAnalysis;
    using System.IO;
    using System.Linq;
    using System.Text;
    using System.Text.Json;
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
        /// <summary>
        ///     Encrypts this <typeparamref name="TSource"/> object with the specified
        ///     algorithm and returns the 64-bit unsigned integer representation of the
        ///     computed hash code.
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
        ///     A 64-bit unsigned integer that contains the result of encrypting the
        ///     specified object by the specified algorithm.
        /// </returns>
        public static ulong GetCipher<TSource>(this TSource source, ChecksumAlgo algorithm = ChecksumAlgo.Sha256) =>
            InternalGenericEncrypt(source, algorithm).HashNumber;

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
        [return: NotNullIfNotNull("source")]
        public static string GetGuid<TSource>(this TSource source, bool braces = false, ChecksumAlgo algorithm1 = ChecksumAlgo.Crc32, ChecksumAlgo algorithm2 = ChecksumAlgo.Sha256)
        {
            var sb = new StringBuilder(braces ? 38 : 36);
            if (braces)
                sb.Append('{');
            var raw1 = InternalGenericEncrypt(source, algorithm1, true).RawHash.Span;
            var raw2 = InternalGenericEncrypt(source, algorithm2, true).RawHash.Span;
            var span = CombineHashBytes(raw1, raw2, 16);
            var index = 0;
            for (var i = 0; i < 5; i++)
            {
                var size = i switch { < 1 => 4, < 4 => 2, _ => 6 };
                for (var j = 0; j < size; j++)
                    sb.AppendFormat("{0:x2}", span[index++]);
                if (i < 4)
                    sb.Append('-');
            }
            if (braces)
                sb.Append('}');
            var str = sb.ToString();
            sb.Clear();
            return str;

            static Span<byte> CombineHashBytes(ReadOnlySpan<byte> span1, ReadOnlySpan<byte> span2, int size)
            {
                var ba = new byte[size].AsSpan();
                var i1 = 0;
                var i2 = 0;
                for (var i = 0; i < size; i++)
                {
                    var e1 = span1.IsEmpty ? byte.MinValue : span1[i1 < span1.Length ? i1++ : i1 = 0];
                    var e2 = span2.IsEmpty ? byte.MaxValue : span2[i2 < span2.Length ? i2++ : i2 = 0];
                    ba[i] = (byte)CryptoUtils.CombineHashCodes(e1, e2);
                }
                return ba;
            }
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
        [return: NotNullIfNotNull("source")]
        public static string Encrypt<TSource>(this TSource source, ChecksumAlgo algorithm = ChecksumAlgo.Sha256) =>
            InternalGenericEncrypt(source, algorithm).Hash;

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
        ///     Creates a default instance of this algorithm.
        /// </summary>
        /// <param name="algorithm">
        ///     The algorithm to use.
        /// </param>
        /// <returns>
        ///     A default instance of the specified algorithm.
        /// </returns>
        public static IChecksumAlgorithm GetDefaultInstance(this ChecksumAlgo algorithm) =>
            algorithm switch
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
            };

        private static IChecksumAlgorithm InternalGenericEncrypt<TSource>(TSource source, ChecksumAlgo algorithm, bool ifStreamRestorePos = false)
        {
            if (source == null)
                throw new ArgumentNullException(nameof(source));
            var instance = algorithm.GetDefaultInstance();
            switch (source)
            {
                case Stream stream:

                    var pos = ifStreamRestorePos ? stream.Position : -1L;
                    instance.Encrypt(stream);
                    if (pos >= 0)
                        stream.Position = pos;
                    break;
                case IEnumerable<byte> bytes:
                    instance.Encrypt(bytes as byte[] ?? bytes.ToArray());
                    break;
                case IEnumerable<char> chars:
                    instance.Encrypt(chars as string ?? new string(chars.ToArray()));
                    break;
                default:
                    using (var ms = new MemoryStream())
                    {
                        using var bw = new Utf8JsonWriter(ms, new JsonWriterOptions { SkipValidation = true });
                        JsonSerializer.Serialize(bw, source);
                        ms.Position = 0L;
                        instance.Encrypt(ms);
                    }
                    break;
            }
            return instance;
        }
    }
}
