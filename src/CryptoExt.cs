namespace Roydl.Crypto
{
    using System.Collections.Generic;
    using System.IO;
    using System.Linq;
    using System.Text;
    using System.Text.Json;
    using Checksum;

    /// <summary>
    ///     Specifies enumerated constants used to encode and decode data.
    /// </summary>
    public enum BinaryToTextEncoding
    {
        /// <summary>
        ///     Binary.
        /// </summary>
        Radix2,

        /// <summary>
        ///     Octal.
        /// </summary>
        Radix8,

        /// <summary>
        ///     Decimal.
        /// </summary>
        RadixA,

        /// <summary>
        ///     Hexadecimal.
        /// </summary>
        RadixF,

        /// <summary>
        ///     Base32.
        /// </summary>
        Base32,

        /// <summary>
        ///     Base64.
        /// </summary>
        Base64,

        /// <summary>
        ///     Base85 (Ascii85).
        /// </summary>
        Base85,

        /// <summary>
        ///     Base91 (basE91).
        /// </summary>
        Base91
    }

    /// <summary>
    ///     Specifies enumerated constants used to encrypt data.
    /// </summary>
    public enum ChecksumAlgorithm
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
    public static class CryptoExt
    {
        /// <summary>
        ///     Encrypts this <typeparamref name="TSource"/> object with the specified
        ///     <see cref="ChecksumAlgorithm"/> and combines both hashes into a unique
        ///     GUID.
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
        public static string GetGuid<TSource>(this TSource source, bool braces = false, ChecksumAlgorithm algorithm1 = ChecksumAlgorithm.Crc32, ChecksumAlgorithm algorithm2 = ChecksumAlgorithm.Sha256)
        {
            var sb = new StringBuilder(braces ? 38 : 36);
            Utils.CombineHashes(sb, source?.Encrypt(algorithm1), source?.Encrypt(algorithm2), braces);
            var s = sb.ToString();
            sb.Clear();
            return s;
        }

        /// <summary>
        ///     Encodes this sequence of bytes with the specified algorithm.
        /// </summary>
        /// <param name="bytes">
        ///     The sequence of bytes to encode.
        /// </param>
        /// <param name="algorithm">
        ///     The algorithm to use.
        /// </param>
        public static string Encode(this byte[] bytes, BinaryToTextEncoding algorithm = BinaryToTextEncoding.Base64) =>
            Utils.GetDefaultInstance(algorithm).EncodeBytes(bytes);

        /// <summary>
        ///     Encodes this string with the specified algorithm.
        /// </summary>
        /// <param name="text">
        ///     The string to encode.
        /// </param>
        /// <param name="algorithm">
        ///     The algorithm to use.
        /// </param>
        public static string Encode(this string text, BinaryToTextEncoding algorithm = BinaryToTextEncoding.Base64) =>
            Utils.GetDefaultInstance(algorithm).EncodeString(text);

        /// <summary>
        ///     Encodes this file with the specified algorithm.
        /// </summary>
        /// <param name="path">
        ///     The full path of the file to encode.
        /// </param>
        /// <param name="algorithm">
        ///     The algorithm to use.
        /// </param>
        public static string EncodeFile(this string path, BinaryToTextEncoding algorithm = BinaryToTextEncoding.Base64) =>
            Utils.GetDefaultInstance(algorithm).EncodeFile(path);

        /// <summary>
        ///     Decodes this string into a sequence of bytes with the specified algorithm.
        /// </summary>
        /// <param name="code">
        ///     The string to decode.
        /// </param>
        /// <param name="algorithm">
        ///     The algorithm to use.
        /// </param>
        public static byte[] Decode(this string code, BinaryToTextEncoding algorithm = BinaryToTextEncoding.Base64) =>
            Utils.GetDefaultInstance(algorithm).DecodeBytes(code);

        /// <summary>
        ///     Decodes this string into a sequence of bytes with the specified algorithm.
        /// </summary>
        /// <param name="code">
        ///     The string to decode.
        /// </param>
        /// <param name="algorithm">
        ///     The algorithm to use.
        /// </param>
        public static string DecodeString(this string code, BinaryToTextEncoding algorithm = BinaryToTextEncoding.Base64) =>
            Utils.GetDefaultInstance(algorithm).DecodeString(code);

        /// <summary>
        ///     Decodes this file into a sequence of bytes with the specified algorithm.
        /// </summary>
        /// <param name="path">
        ///     The full path of the file to decode.
        /// </param>
        /// <param name="algorithm">
        ///     The algorithm to use.
        /// </param>
        public static byte[] DecodeFile(this string path, BinaryToTextEncoding algorithm = BinaryToTextEncoding.Base64) =>
            Utils.GetDefaultInstance(algorithm).DecodeFile(path);

        /// <summary>
        ///     Encrypts this <typeparamref name="TSource"/> object with the
        ///     <see cref="ChecksumAlgorithm.Crc32"/> algorithm.
        /// </summary>
        /// <typeparam name="TSource">
        ///     The type of source.
        /// </typeparam>
        /// <param name="source">
        ///     The object to encrypt.
        /// </param>
        public static uint EncryptRaw<TSource>(this TSource source)
        {
            var instance = (Crc32)Utils.GetDefaultInstance(ChecksumAlgorithm.Crc32);
            switch (source)
            {
                case null:
                    return 0u;
                case Stream stream:
                    instance.Encrypt(stream);
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
            return instance.RawHash;
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
        public static string Encrypt<TSource>(this TSource source, ChecksumAlgorithm algorithm = ChecksumAlgorithm.Sha256)
        {
            var instance = Utils.GetDefaultInstance(algorithm);
            switch (source)
            {
                case Stream stream:
                    instance.Encrypt(stream);
                    return instance.Hash;
                case IEnumerable<byte> bytes:
                    instance.Encrypt(bytes as byte[] ?? bytes.ToArray());
                    return instance.Hash;
                case IEnumerable<char> chars:
                    instance.Encrypt(chars as string ?? new string(chars.ToArray()));
                    return instance.Hash;
            }
            using var ms = new MemoryStream();
            using var bw = new Utf8JsonWriter(ms, new JsonWriterOptions { SkipValidation = true });
            JsonSerializer.Serialize(bw, source);
            ms.Position = 0L;
            instance.Encrypt(ms);
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
        public static string EncryptFile(this string path, ChecksumAlgorithm algorithm = ChecksumAlgorithm.Sha256)
        {
            var instance = Utils.GetDefaultInstance(algorithm);
            instance.EncryptFile(path);
            return instance.Hash;
        }
    }
}
