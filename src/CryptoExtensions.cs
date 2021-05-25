namespace Roydl.Crypto
{
    using System;
    using System.Collections;
    using System.Collections.Generic;
    using System.Diagnostics.CodeAnalysis;
    using System.IO;
    using System.Linq;
    using System.Runtime.Serialization;
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
        ///     Encrypts this <paramref name="source"/> object with the specified
        ///     <paramref name="algorithm"/> and returns the 64-bit unsigned integer
        ///     representation of the computed hash code.
        /// </summary>
        /// <exception cref="ArgumentNullException">
        ///     source is null.
        /// </exception>
        /// <exception cref="ArgumentException">
        ///     source is empty.
        /// </exception>
        /// <exception cref="FileNotFoundException">
        ///     source cannot be found.
        /// </exception>
        /// <exception cref="UnauthorizedAccessException">
        ///     source is a directory.
        /// </exception>
        /// <exception cref="IOException">
        ///     source is already open, or an I/O error occurs.
        /// </exception>
        /// <exception cref="NotSupportedException">
        ///     source does not support reading.
        /// </exception>
        /// <returns>
        ///     A 64-bit unsigned integer that contains the result of encrypting the
        ///     specified <paramref name="source"/> object by the specified
        ///     <paramref name="algorithm"/>.
        /// </returns>
        /// <inheritdoc cref="TryGetCipher{TSource}(TSource, ChecksumAlgo, out ulong)"/>
        public static ulong GetCipher<TSource>(this TSource source, ChecksumAlgo algorithm = ChecksumAlgo.Sha256) =>
            InternalGenericEncrypt(source, algorithm, false).HashNumber;

        /// <returns>
        ///     A string that contains the result of encrypting the specified
        ///     <paramref name="source"/> object by the specified
        ///     <paramref name="algorithm"/>.
        /// </returns>
        /// <inheritdoc cref="GetCipher{TSource}(TSource, ChecksumAlgo)"/>
        [return: NotNullIfNotNull("source")]
        public static string GetChecksum<TSource>(this TSource source, ChecksumAlgo algorithm = ChecksumAlgo.Sha256) =>
            InternalGenericEncrypt(source, algorithm, false).Hash;

        /// <summary>
        ///     Encrypts the file at this <paramref name="path"/> with the specified
        ///     <paramref name="algorithm"/>.
        /// </summary>
        /// <param name="path">
        ///     The full path of the file to encrypt.
        /// </param>
        /// <param name="algorithm">
        ///     The algorithm to use.
        /// </param>
        /// <returns>
        ///     A string that contains the result of encrypting the file at specified
        ///     <paramref name="path"/> by the specified <paramref name="algorithm"/>.
        /// </returns>
        /// <inheritdoc cref="IChecksumAlgorithm.EncryptFile(string)"/>
        public static string GetFileChecksum(this string path, ChecksumAlgo algorithm = ChecksumAlgo.Sha256)
        {
            var instance = algorithm.GetDefaultInstance();
            instance.EncryptFile(path);
            return instance.Hash;
        }

        /// <summary>
        ///     Encrypts this <paramref name="source"/> object with the specified
        ///     <paramref name="algorithm1"/> and the specified
        ///     <paramref name="algorithm2"/> and combines the bytes of both hashes into a
        ///     unique GUID string.
        /// </summary>
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
        ///     A string with a GUID that contains the results of encrypting the specified
        ///     <paramref name="source"/> object by the specified
        ///     <paramref name="algorithm1"/> and the specified
        ///     <paramref name="algorithm2"/>.
        /// </returns>
        /// <inheritdoc cref="GetCipher{TSource}(TSource, ChecksumAlgo)"/>
        [return: NotNullIfNotNull("source")]
        public static string GetGuid<TSource>(this TSource source, bool braces = false, ChecksumAlgo algorithm1 = ChecksumAlgo.Crc32, ChecksumAlgo algorithm2 = ChecksumAlgo.Sha256)
        {
            var sb = new StringBuilder(braces ? 38 : 36);
            if (braces)
                sb.Append('{');
            var raw1 = InternalGenericEncrypt(source, algorithm1, true).RawHash.Span;
            var raw2 = InternalGenericEncrypt(source, algorithm2, false).RawHash.Span;
            var span = LocalCombineHashBytes(raw1, raw2, 16);
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

            static Span<byte> LocalCombineHashBytes(ReadOnlySpan<byte> span1, ReadOnlySpan<byte> span2, int size)
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
        ///     Tries to encrypt this <paramref name="source"/> object with the specified
        ///     <paramref name="algorithm"/> and returns a <see cref="bool"/> value that
        ///     determines whether the encryption was successful. All possible exceptions
        ///     are caught.
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
        /// <param name="hash">
        ///     If successful, the result of encrypting the specified
        ///     <paramref name="source"/> object by the specified
        ///     <paramref name="algorithm"/>; otherwise, <see langword="default"/>.
        /// </param>
        /// <remarks>
        ///     <list type="bullet">
        ///         <item>
        ///             If <paramref name="source"/> is <see cref="Stream"/>:
        ///             <description>
        ///                 <see cref="IChecksumAlgorithm.Encrypt(Stream)"/> is used to
        ///                 encrypt the bytes of stream.
        ///             </description>
        ///         </item>
        ///         <item>
        ///             If <paramref name="source"/> is <see cref="FileInfo"/>:
        ///             <description>
        ///                 <see cref="IChecksumAlgorithm.Encrypt(FileInfo)"/> is used to
        ///                 read and encrypt the file, if exist and accessible.
        ///             </description>
        ///         </item>
        ///         <item>
        ///             If <paramref name="source"/> is <see cref="IEnumerable"/>&lt;
        ///             <see cref="byte"/>&gt;:
        ///             <description>
        ///                 <see cref="IChecksumAlgorithm.Encrypt(byte[])"/> is used to
        ///                 encrypt the bytes.
        ///             </description>
        ///         </item>
        ///         <item>
        ///             If <paramref name="source"/> is <see cref="IEnumerable"/>&lt;
        ///             <see cref="char"/>&gt;:
        ///             <description>
        ///                 <see cref="IChecksumAlgorithm.Encrypt(string)"/> is used to
        ///                 encrypt the string.
        ///             </description>
        ///         </item>
        ///         <item>
        ///             Otherwise:
        ///             <description>
        ///                 The values of <paramref name="source"/> are serialized using
        ///                 <see cref="Utf8JsonWriter"/> with skipped validation and the
        ///                 result is encrypted, even if <paramref name="source"/> is not
        ///                 <see cref="ISerializable"/>. This can be useful for comparing
        ///                 types that normally cannot be easily compared.
        ///             </description>
        ///         </item>
        ///     </list>
        /// </remarks>
        /// <returns>
        ///     <see langword="true"/> if the specified <paramref name="source"/> could be
        ///     encrypted by the specified <paramref name="algorithm"/>; otherwise,
        ///     <see langword="false"/> .
        /// </returns>
        public static bool TryGetCipher<TSource>(this TSource source, ChecksumAlgo algorithm, out ulong hash)
        {
            try
            {
                hash = source.GetCipher(algorithm);
                return hash > 0;
            }
            catch
            {
                hash = default;
                return false;
            }
        }

        /// <summary>
        ///     Encrypts this <paramref name="source"/> object with the
        ///     <see cref="ChecksumAlgo.Sha256"/> algorithm and returns a
        ///     <see cref="bool"/> value that determines whether the encryption was
        ///     successful. All possible exceptions are caught.
        /// </summary>
        /// <typeparam name="TSource">
        ///     The type of source.
        /// </typeparam>
        /// <param name="source">
        ///     The object to encrypt.
        /// </param>
        /// <param name="hash">
        ///     If successful, the result of encrypting the specified
        ///     <paramref name="source"/> object by the <see cref="ChecksumAlgo.Sha256"/>
        ///     algorithm; otherwise, <see langword="default"/>.
        /// </param>
        /// <returns>
        ///     <see langword="true"/> if the specified <paramref name="source"/> could be
        ///     encrypted by the <see cref="ChecksumAlgo.Sha256"/> algorithm; otherwise,
        ///     <see langword="false"/> .
        /// </returns>
        /// <inheritdoc cref="TryGetCipher{TSource}(TSource, ChecksumAlgo, out ulong)"/>
        public static bool TryGetCipher<TSource>(this TSource source, out ulong hash) =>
            source.TryGetCipher(ChecksumAlgo.Sha256, out hash);

        /// <inheritdoc cref="TryGetCipher{TSource}(TSource, ChecksumAlgo, out ulong)"/>
        public static bool TryGetChecksum<TSource>(this TSource source, ChecksumAlgo algorithm, out string hash)
        {
            try
            {
                hash = source.GetChecksum(algorithm);
                return !string.IsNullOrEmpty(hash);
            }
            catch
            {
                hash = default;
                return false;
            }
        }

        /// <inheritdoc cref="TryGetCipher{TSource}(TSource, out ulong)"/>
        public static bool TryGetChecksum<TSource>(this TSource source, out string hash) =>
            source.TryGetChecksum(ChecksumAlgo.Sha256, out hash);

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

        private static IChecksumAlgorithm InternalGenericEncrypt<TSource>(TSource source, ChecksumAlgo algorithm, bool ifStreamRestorePos)
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
                case FileInfo file:
                    instance.Encrypt(file);
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

        #region Obsolete

        /// <inheritdoc cref="GetChecksum{TSource}(TSource, ChecksumAlgo)"/>
        [Obsolete("Please use `GetChecksum` instead. This extension will be removed in the next version.")]
        [return: NotNullIfNotNull("source")]
        public static string Encrypt<TSource>(this TSource source, ChecksumAlgo algorithm = ChecksumAlgo.Sha256) =>
            source?.GetChecksum(algorithm);

        /// <inheritdoc cref="GetFileChecksum(string, ChecksumAlgo)"/>
        [Obsolete("Please use `GetFileChecksum` instead. This extension will be removed in the next version.")]
        public static string EncryptFile(this string path, ChecksumAlgo algorithm = ChecksumAlgo.Sha256) =>
            path?.GetFileChecksum(algorithm);

        #endregion
    }
}
