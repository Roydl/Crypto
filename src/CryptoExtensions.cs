namespace Roydl.Crypto
{
    using System;
    using System.Collections.Generic;
    using System.Diagnostics.CodeAnalysis;
    using System.IO;
    using System.Linq;
    using System.Numerics;
    using System.Runtime.InteropServices;
    using System.Text;
    using System.Text.Json;
    using Checksum;

    /// <summary>Specifies enumerated constants used to define an algorithm for encrypting data.</summary>
    public enum ChecksumAlgo
    {
        /// <summary>Adler-32.</summary>
        Adler32,

        /// <summary>CRC-16 (Cyclic Redundancy Check).</summary>
        Crc16,

        /// <summary>CRC-32 (Cyclic Redundancy Check).</summary>
        Crc32,

        /// <summary>CRC-64 (Cyclic Redundancy Check).</summary>
        Crc64,

        /// <summary>MD5 (Message-Digest 5).</summary>
        Md5,

        /// <summary>SHA-1 (Secure Hash Algorithm 1).</summary>
        Sha1,

        /// <summary>SHA-256 (Secure Hash Algorithm 2).</summary>
        Sha256,

        /// <summary>SHA-384 (Secure Hash Algorithm 2).</summary>
        Sha384,

        /// <summary>SHA-512 (Secure Hash Algorithm 2).</summary>
        Sha512
    }

    /// <summary>Provides extension methods for data encryption and decryption.</summary>
    public static class CryptoExtensions
    {
        /// <summary>Encrypts this <paramref name="source"/> object with the specified <paramref name="algorithm"/> and returns the 64-bit unsigned integer representation of the computed hash code.</summary>
        /// <exception cref="ArgumentNullException">source is null.</exception>
        /// <exception cref="ArgumentException">source is empty.</exception>
        /// <exception cref="FileNotFoundException">source cannot be found.</exception>
        /// <exception cref="UnauthorizedAccessException">source is a directory.</exception>
        /// <exception cref="IOException">source is already open, or an I/O error occurs.</exception>
        /// <exception cref="NotSupportedException">source does not support reading.</exception>
        /// <returns>A 64-bit unsigned integer that contains the result of encrypting the specified <paramref name="source"/> object by the specified <paramref name="algorithm"/>.</returns>
        /// <inheritdoc cref="TryGetCipher{TSource}(TSource, ChecksumAlgo, out ulong)"/>
        public static ulong GetCipher<TSource>(this TSource source, ChecksumAlgo algorithm = ChecksumAlgo.Sha256) =>
            InternalGenericEncrypt(source, algorithm, false).HashNumber;

        /// <summary>Encrypts this <paramref name="source"/> object with the specified <paramref name="algorithm"/> and returns the string representation of the computed hash code.</summary>
        /// <returns>A string that contains the result of encrypting the specified <paramref name="source"/> object by the specified <paramref name="algorithm"/>.</returns>
        /// <inheritdoc cref="GetCipher{TSource}(TSource, ChecksumAlgo)"/>
        [return: NotNullIfNotNull("source")]
        public static string GetChecksum<TSource>(this TSource source, ChecksumAlgo algorithm = ChecksumAlgo.Sha256) =>
            InternalGenericEncrypt(source, algorithm, false).Hash;

        /// <summary>Encrypts the file at this <paramref name="path"/> with the specified <paramref name="algorithm"/> and returns the string representation of the computed hash code.</summary>
        /// <param name="path">The full path of the file to encrypt.</param>
        /// <param name="algorithm">The algorithm to use.</param>
        /// <returns>A string that contains the result of encrypting the file at specified <paramref name="path"/> by the specified <paramref name="algorithm"/>.</returns>
        /// <inheritdoc cref="IChecksumAlgorithm.EncryptFile(string)"/>
        public static string GetFileChecksum(this string path, ChecksumAlgo algorithm = ChecksumAlgo.Sha256)
        {
            var instance = algorithm.GetDefaultInstance();
            instance.EncryptFile(path);
            return instance.Hash;
        }

        /// <summary>Encrypts this <paramref name="source"/> object with the specified <paramref name="algorithm1"/> and the specified <paramref name="algorithm2"/> and combines the bytes of both hashes into a unique GUID string.</summary>
        /// <param name="source">The object to encrypt.</param>
        /// <param name="braces"><see langword="true"/> to place the GUID between braces; otherwise, <see langword="false"/>.</param>
        /// <param name="algorithm1">The first algorithm to use.</param>
        /// <param name="algorithm2">The second algorithm to use.</param>
        /// <returns>A string with a GUID that contains the results of encrypting the specified <paramref name="source"/> object by the specified <paramref name="algorithm1"/> and the specified <paramref name="algorithm2"/>.</returns>
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

#if NETCOREAPP3_1
#pragma warning disable CS1574 // XML comment has cref attribute that could not be resolved
#endif
        /// <summary>Tries to encrypt this <paramref name="source"/> object with the specified <paramref name="algorithm"/> and returns a <see cref="bool"/> value that determines whether the encryption was successful. All possible exceptions are caught.</summary>
        /// <typeparam name="TSource">The type of source.</typeparam>
        /// <param name="source">The object to encrypt.</param>
        /// <param name="algorithm">The algorithm to use.</param>
        /// <param name="hash">If successful, the result of encrypting the specified <paramref name="source"/> object by the specified <paramref name="algorithm"/>; otherwise, <see langword="default"/>.</param>
        /// <remarks>
        ///     <list type="table">
        ///         <item><term>Known</term>&#160;<description><see cref="bool"/>, <see cref="sbyte"/>, <see cref="byte"/>, <see cref="short"/>, <see cref="ushort"/>, <see cref="char"/>, <see cref="int"/>, <see cref="uint"/>, <see cref="long"/>, <see cref="ulong"/>, <see cref="Half"/>, <see cref="float"/>, <see cref="double"/>, <see cref="decimal"/>, <see cref="Enum"/>, <see cref="IntPtr"/>, <see cref="UIntPtr"/>, <see cref="Vector{T}"/>, <see cref="Vector2"/>, <see cref="Vector3"/>, <see cref="Vector4"/>, <see cref="Matrix3x2"/>, <see cref="Matrix4x4"/>, <see cref="Plane"/>, <see cref="Quaternion"/>, <see cref="Complex"/>, <see cref="BigInteger"/>, <see cref="DateTime"/>, <see cref="DateTimeOffset"/>, <see cref="TimeSpan"/>, <see cref="Guid"/>, <see cref="Rune"/>, <see cref="Stream"/>, <see cref="StreamReader"/>, <see cref="FileInfo"/>, any <see cref="IEnumerable{T}"/> <see cref="byte"/> sequence, i.e. <see cref="Array"/>, or any <see cref="IEnumerable{T}"/> <see cref="char"/> sequence, i.e. <see cref="string"/>.</description></item>
        ///         <item><term>Otherwise</term>&#160;<description>An attempt is made to convert <paramref name="source"/> to a byte array for the encryption, which should work for all <see href="https://docs.microsoft.com/en-us/dotnet/framework/interop/blittable-and-non-blittable-types">blittable types</see>. If this fails, <paramref name="source"/> is serialized using <see cref="Utf8JsonWriter"/> and the result is encrypted.</description></item>
        ///     </list>
        /// </remarks>
        /// <returns><see langword="true"/> if the specified <paramref name="source"/> could be encrypted by the specified <paramref name="algorithm"/>; otherwise, <see langword="false"/>.</returns>
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
#if NETCOREAPP3_1
#pragma warning restore CS1574 // XML comment has cref attribute that could not be resolved
#endif

        /// <summary>Encrypts this <paramref name="source"/> object with the <see cref="ChecksumAlgo.Sha256"/> algorithm and returns a <see cref="bool"/> value that determines whether the encryption was successful. All possible exceptions are caught.</summary>
        /// <typeparam name="TSource">The type of source.</typeparam>
        /// <param name="source">The object to encrypt.</param>
        /// <param name="hash">If successful, the result of encrypting the specified <paramref name="source"/> object by the <see cref="ChecksumAlgo.Sha256"/> algorithm; otherwise, <see langword="default"/>.</param>
        /// <returns><see langword="true"/> if the specified <paramref name="source"/> could be encrypted by the <see cref="ChecksumAlgo.Sha256"/> algorithm; otherwise, <see langword="false"/>.</returns>
        /// <inheritdoc cref="TryGetCipher{TSource}(TSource, ChecksumAlgo, out ulong)"/>
        public static bool TryGetCipher<TSource>(this TSource source, out ulong hash) =>
            source.TryGetCipher(ChecksumAlgo.Sha256, out hash);

        /// <inheritdoc cref="TryGetCipher{TSource}(TSource, ChecksumAlgo, out ulong)"/>
        public static bool TryGetChecksum<TSource>(this TSource source, ChecksumAlgo algorithm, [NotNullWhen(true)] out string hash)
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
        public static bool TryGetChecksum<TSource>(this TSource source, [NotNullWhen(true)] out string hash) =>
            source.TryGetChecksum(ChecksumAlgo.Sha256, out hash);

        /// <summary>Creates a default instance of this algorithm.</summary>
        /// <param name="algorithm">The algorithm to use.</param>
        /// <returns>A default instance of the specified algorithm.</returns>
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
                case BigInteger x:
                    instance.Encrypt(x.ToByteArray());
                    break;
                case char x:
                    instance.Encrypt(x.ToString());
                    break;
                case IEnumerable<byte> x:
                    instance.Encrypt(x as byte[] ?? x.ToArray());
                    break;
                case IEnumerable<char> x:
                    instance.Encrypt(x as string ?? new string(x.ToArray()));
                    break;
                case StreamReader x:
                    LocalProcessStream(instance, x.BaseStream, ifStreamRestorePos);
                    break;
                case Stream x:
                    LocalProcessStream(instance, x, ifStreamRestorePos);
                    break;
                case FileInfo x:
                    instance.Encrypt(x);
                    break;
                default:
#if DEBUG
                    instance.Encrypt(LocalGetByteArray(source));
#else
                    try
                    {
                        // Blittable types:
                        // https://docs.microsoft.com/dotnet/framework/interop/blittable-and-non-blittable-types
                        // sbyte, byte, short, ushort, char, int, uint, long, ulong, Half, float, double, decimal,
                        // Enum, IntPtr, UIntPtr, Vector{T}, Vector2, Vector3, Vector4, Matrix3x2, Matrix4x4, Plane,
                        // Quaternion, Complex, Guid, Rune, and more.
                        instance.Encrypt(LocalGetByteArray(source));
                    }
                    catch (ArgumentException)
                    {
                        // Fallback
                        using var ms = new MemoryStream();
                        using var jw = new Utf8JsonWriter(ms, new JsonWriterOptions { SkipValidation = true });
                        JsonSerializer.Serialize(jw, source);
                        ms.Position = 0L;
                        instance.Encrypt(ms);
                    }
#endif
                    break;
            }
            return instance;

            static byte[] LocalGetByteArray(object value)
            {
                value = value switch
                {
                    bool x => x ? 1 : 0,
                    TimeSpan x => x.TotalMilliseconds,
                    DateTime x => new DateTimeOffset(x).ToUnixTimeMilliseconds(),
                    DateTimeOffset x => x.ToUnixTimeMilliseconds(),
                    _ => value
                };
                var size = Marshal.SizeOf(value);
                var handle = GCHandle.Alloc(value, GCHandleType.Pinned);
                var bytes = new byte[size];
                Marshal.Copy(handle.AddrOfPinnedObject(), bytes, 0, bytes.Length);
                handle.Free();
                return bytes;
            }

            static void LocalProcessStream(IChecksumAlgorithm instance, Stream stream, bool restorePos)
            {
                var pos = restorePos ? stream.Position : -1L;
                instance.Encrypt(stream);
                if (restorePos && pos >= 0)
                    stream.Position = pos;
            }
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
