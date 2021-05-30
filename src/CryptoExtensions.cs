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

        /// <summary>CRC-16/USB.</summary>
        /// <remarks>Equal to <see cref="Crc16Usb"/>.</remarks>
        Crc16,

        /// <summary>CRC-16/USB.</summary>
        /// <remarks>Equal to <see cref="Crc16"/>.</remarks>
        Crc16Usb = Crc16,

        /// <summary>CRC-16/A.</summary>
        Crc16A,

        /// <summary>CRC-16/ARC.</summary>
        Crc16Arc,

        /// <summary>CRC-16/AUG-CCITT.</summary>
        Crc16AugCcitt,

        /// <summary>CRC-16/BUYPASS.</summary>
        Crc16Buypass,

        /// <summary>CRC-16/CCITT-FALSE.</summary>
        Crc16CcittFalse,

        /// <summary>CRC-16/CDMA2000.</summary>
        Crc16Cdma2000,

        /// <summary>CRC-16/DDS-110.</summary>
        Crc16Dds110,

        /// <summary>CRC-16/DECT-R.</summary>
        Crc16DectR,

        /// <summary>CRC-16/DECT-X.</summary>
        Crc16DectX,

        /// <summary>CRC-16/DNP.</summary>
        Crc16Dnp,

        /// <summary>CRC-16/EN-13757.</summary>
        Crc16En13757,

        /// <summary>CRC-16/GENIBUS.</summary>
        Crc16Genibus,

        /// <summary>CRC-16/KERMIT.</summary>
        Crc16Kermit,

        /// <summary>CRC-16/MAXIM.</summary>
        Crc16Maxim,

        /// <summary>CRC-16/MCRF4XX.</summary>
        Crc16Mcrf4Xx,

        /// <summary>CRC-16/MODBUS.</summary>
        Crc16ModBus,

        /// <summary>CRC-16/RIELLO.</summary>
        Crc16Riello,

        /// <summary>CRC-16/T10-DIF.</summary>
        Crc16T10Dif,

        /// <summary>CRC-16/TELEDISK.</summary>
        Crc16TeleDisk,

        /// <summary>CRC-16/TMS37157.</summary>
        Crc16Tms37157,

        /// <summary>CRC-16/XMODEM.</summary>
        Crc16XModem,

        /// <summary>CRC-16/X-25.</summary>
        Crc16X25,

        /// <summary>CRC-17/CAN-FD.</summary>
        /// <remarks>Equal to <see cref="Crc17CanFd"/>.</remarks>
        Crc17,

        /// <summary>CRC-17/CAN-FD.</summary>
        /// <remarks>Equal to <see cref="Crc17"/>.</remarks>
        Crc17CanFd = Crc17,

        /// <summary>CRC-21/CAN-FD.</summary>
        /// <remarks>Equal to <see cref="Crc21CanFd"/>.</remarks>
        Crc21,

        /// <summary>CRC-21/CAN-FD.</summary>
        /// <remarks>Equal to <see cref="Crc21"/>.</remarks>
        Crc21CanFd = Crc21,

        /// <summary>CRC-24/OPENPGP.</summary>
        /// <remarks>Equal to <see cref="Crc24OpenPgp"/>.</remarks>
        Crc24,

        /// <summary>CRC-24/OPENPGP.</summary>
        /// <remarks>Equal to <see cref="Crc24"/>.</remarks>
        Crc24OpenPgp = Crc24,

        /// <summary>CRC-24/BLE.</summary>
        Crc24Ble,

        /// <summary>CRC-24/LTE-A.</summary>
        Crc24LteA,

        /// <summary>CRC-24/LTE-B.</summary>
        Crc24LteB,

        /// <summary>CRC-24/FLEXRAY-A.</summary>
        Crc24FlexRayA,

        /// <summary>CRC-24/FLEXRAY-B.</summary>
        Crc24FlexRayB,

        /// <summary>CRC-24/INTERLAKEN.</summary>
        Crc24Interlaken,

        /// <summary>CRC-24/OS-9.</summary>
        Crc24Os9,

        /// <summary>CRC-30/CDMA.</summary>
        /// <remarks>Equal to <see cref="Crc30Cdma"/>.</remarks>
        Crc30,

        /// <summary>CRC-30/CDMA.</summary>
        /// <remarks>Equal to <see cref="Crc30"/>.</remarks>
        Crc30Cdma = Crc30,

        /// <summary>CRC-31/PHILIPS.</summary>
        /// <remarks>Equal to <see cref="Crc31Philips"/>.</remarks>
        Crc31,

        /// <summary>CRC-31/PHILIPS.</summary>
        /// <remarks>Equal to <see cref="Crc31"/>.</remarks>
        Crc31Philips = Crc31,

        /// <summary>CRC-32/ISO-HDLC.</summary>
        /// <remarks>Equal to <see cref="Crc32Adccp"/>, <see cref="Crc32IsoHdlc"/>, <see cref="Crc32PkZip"/>, <see cref="Crc32V24"/> and <see cref="Crc32Xz"/>.</remarks>
        Crc32,

        /// <summary>CRC-32/ADCCP.</summary>
        /// <remarks>Equal to <see cref="Crc32"/>, <see cref="Crc32PkZip"/>, <see cref="Crc32V24"/> and <see cref="Crc32Xz"/>.</remarks>
        Crc32Adccp = Crc32,

        /// <summary>CRC-32/ISO-HDLC.</summary>
        /// <remarks>Equal to <see cref="Crc32"/>, <see cref="Crc32Adccp"/>, <see cref="Crc32PkZip"/>, <see cref="Crc32V24"/> and <see cref="Crc32Xz"/>.</remarks>
        Crc32IsoHdlc = Crc32,

        /// <summary>CRC-32/PKZip.</summary>
        /// <remarks>Equal to <see cref="Crc32"/>, <see cref="Crc32Adccp"/>, <see cref="Crc32IsoHdlc"/>, <see cref="Crc32V24"/> and <see cref="Crc32Xz"/>.</remarks>
        Crc32PkZip = Crc32,

        /// <summary>CRC-32/V-24.</summary>
        /// <remarks>Equal to <see cref="Crc32"/>, <see cref="Crc32Adccp"/>, <see cref="Crc32IsoHdlc"/>, <see cref="Crc32PkZip"/> and <see cref="Crc32Xz"/>.</remarks>
        Crc32V24 = Crc32,

        /// <summary>CRC-32/XZ.</summary>
        /// <remarks>Equal to <see cref="Crc32"/>, <see cref="Crc32Adccp"/>, <see cref="Crc32IsoHdlc"/>, <see cref="Crc32PkZip"/> and <see cref="Crc32V24"/>.</remarks>
        Crc32Xz = Crc32,

        /// <summary>CRC-32/AUTOSAR.</summary>
        Crc32Autosar,

        /// <summary>CRC-32/CD-ROM-EDC.</summary>
        Crc32CdRomEdc,

        /// <summary>CRC-32/Q.</summary>
        /// <remarks>Equal to <see cref="Crc32Aixm"/>.</remarks>
        Crc32Q,

        /// <summary>CRC-32/AIXM.</summary>
        /// <remarks>Equal to <see cref="Crc32Q"/>.</remarks>
        Crc32Aixm = Crc32Q,

        /// <summary>CRC-32/BZIP2.</summary>
        /// <remarks>Equal to <see cref="Crc32AaL5"/>, <see cref="Crc32DectB"/> and <see cref="Crc32BCrc"/>.</remarks>
        Crc32BZip2,

        /// <summary>CRC-32/AAL5.</summary>
        /// <remarks>Equal to <see cref="Crc32BZip2"/>, <see cref="Crc32DectB"/> and <see cref="Crc32BCrc"/>.</remarks>
        Crc32AaL5 = Crc32BZip2,

        /// <summary>CRC-32/DECT-B.</summary>
        /// <remarks>Equal to <see cref="Crc32AaL5"/>, <see cref="Crc32BZip2"/> and <see cref="Crc32BCrc"/>.</remarks>
        Crc32DectB = Crc32BZip2,

        /// <summary>CRC-32/B-CRC.</summary>
        /// <remarks>Equal to <see cref="Crc32AaL5"/>, <see cref="Crc32BZip2"/> and <see cref="Crc32DectB"/>.</remarks>
        Crc32BCrc = Crc32BZip2,

        /// <summary>CRC-32/C.</summary>
        /// <remarks>Equal to <see cref="Crc32Base91C"/>, <see cref="Crc32Castagnoli"/>, <see cref="Crc32Interlaken"/> and <see cref="Crc32Iscsi"/>.</remarks>
        Crc32C,

        /// <summary>CRC-32/BASE91-C.</summary>
        /// <remarks>Equal to <see cref="Crc32C"/>, <see cref="Crc32Castagnoli"/>, <see cref="Crc32Interlaken"/> and <see cref="Crc32Iscsi"/>.</remarks>
        Crc32Base91C = Crc32C,

        /// <summary>CRC-32/Castagnoli.</summary>
        /// <remarks>Equal to <see cref="Crc32Base91C"/>, <see cref="Crc32C"/>, <see cref="Crc32Interlaken"/> and <see cref="Crc32Iscsi"/>.</remarks>
        Crc32Castagnoli = Crc32C,

        /// <summary>CRC-32/Interlaken.</summary>
        /// <remarks>Equal to <see cref="Crc32Base91C"/>, <see cref="Crc32C"/>, <see cref="Crc32Castagnoli"/> and <see cref="Crc32Iscsi"/>.</remarks>
        Crc32Interlaken = Crc32C,

        /// <summary>CRC-32/ISCSI.</summary>
        /// <remarks>Equal to <see cref="Crc32Base91C"/>, <see cref="Crc32C"/>, <see cref="Crc32Castagnoli"/> and <see cref="Crc32Interlaken"/>.</remarks>
        Crc32Iscsi = Crc32C,

        /// <summary>CRC-32/D.</summary>
        Crc32D,

        /// <summary>CRC-32/JAMCRC.</summary>
        Crc32JamCrc,

        /// <summary>CRC-32/MPEG-2.</summary>
        Crc32Mpeg2,

        /// <summary>CRC-32/POSIX.</summary>
        /// <remarks>Equal to <see cref="Crc32CkSum"/>.</remarks>
        Crc32Posix,

        /// <summary>CRC-32/CKSUM.</summary>
        /// <remarks>Equal to <see cref="Crc32Posix"/>.</remarks>
        Crc32CkSum = Crc32Posix,

        /// <summary>CRC-32/XFER.</summary>
        Crc32Xfer,

        /// <summary>CRC-40/GSM.</summary>
        /// <remarks>Equal to <see cref="Crc40Gsm"/>.</remarks>
        Crc40,

        /// <summary>CRC-40/GSM.</summary>
        /// <remarks>Equal to <see cref="Crc40"/>.</remarks>
        Crc40Gsm = Crc40,

        /// <summary>CRC-64/ECMA-182.</summary>
        /// <remarks>Equal to <see cref="Crc64Ecma"/>.</remarks>
        Crc64,

        /// <summary>CRC-64/ECMA-182.</summary>
        /// <remarks>Equal to <see cref="Crc64"/>.</remarks>
        Crc64Ecma = Crc64,

        /// <summary>CRC-64/WE.</summary>
        Crc64We,

        /// <summary>CRC-64/XZ.</summary>
        /// <remarks>Equal to <see cref="Crc64GoEcma"/>.</remarks>
        Crc64Xz,

        /// <summary>CRC-64/GO-ECMA.</summary>
        /// <remarks>Equal to <see cref="Crc64Xz"/>.</remarks>
        Crc64GoEcma = Crc64Xz,

        /// <summary>CRC-64/GO-ISO.</summary>
        Crc64GoIso,

        /// <summary>CRC-82/DARC.</summary>
        /// <remarks>Equal to <see cref="Crc82Darc"/>.</remarks>
        Crc82,

        /// <summary>CRC-82/DARC.</summary>
        /// <remarks>Equal to <see cref="Crc82"/>.</remarks>
        Crc82Darc = Crc82,

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

#if NET5_0_OR_GREATER
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
#else
        /// <summary>Tries to encrypt this <paramref name="source"/> object with the specified <paramref name="algorithm"/> and returns a <see cref="bool"/> value that determines whether the encryption was successful. All possible exceptions are caught.</summary>
        /// <typeparam name="TSource">The type of source.</typeparam>
        /// <param name="source">The object to encrypt.</param>
        /// <param name="algorithm">The algorithm to use.</param>
        /// <param name="hash">If successful, the result of encrypting the specified <paramref name="source"/> object by the specified <paramref name="algorithm"/>; otherwise, <see langword="default"/>.</param>
        /// <remarks>
        ///     <list type="table">
        ///         <item><term>Known</term>&#160;<description><see cref="bool"/>, <see cref="sbyte"/>, <see cref="byte"/>, <see cref="short"/>, <see cref="ushort"/>, <see cref="char"/>, <see cref="int"/>, <see cref="uint"/>, <see cref="long"/>, <see cref="ulong"/>, <see cref="float"/>, <see cref="double"/>, <see cref="decimal"/>, <see cref="Enum"/>, <see cref="IntPtr"/>, <see cref="UIntPtr"/>, <see cref="Vector{T}"/>, <see cref="Vector2"/>, <see cref="Vector3"/>, <see cref="Vector4"/>, <see cref="Matrix3x2"/>, <see cref="Matrix4x4"/>, <see cref="Plane"/>, <see cref="Quaternion"/>, <see cref="Complex"/>, <see cref="BigInteger"/>, <see cref="DateTime"/>, <see cref="DateTimeOffset"/>, <see cref="TimeSpan"/>, <see cref="Guid"/>, <see cref="Rune"/>, <see cref="Stream"/>, <see cref="StreamReader"/>, <see cref="FileInfo"/>, any <see cref="IEnumerable{T}"/> <see cref="byte"/> sequence, i.e. <see cref="Array"/>, or any <see cref="IEnumerable{T}"/> <see cref="char"/> sequence, i.e. <see cref="string"/>.</description></item>
        ///         <item><term>Otherwise</term>&#160;<description>An attempt is made to convert <paramref name="source"/> to a byte array for the encryption, which should work for all <see href="https://docs.microsoft.com/en-us/dotnet/framework/interop/blittable-and-non-blittable-types">blittable types</see>. If this fails, <paramref name="source"/> is serialized using <see cref="Utf8JsonWriter"/> and the result is encrypted.</description></item>
        ///     </list>
        /// </remarks>
        /// <returns><see langword="true"/> if the specified <paramref name="source"/> could be encrypted by the specified <paramref name="algorithm"/>; otherwise, <see langword="false"/>.</returns>
#endif
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

        /// <summary>Encrypts this <paramref name="source"/> object with the <see cref="ChecksumAlgo.Sha256"/> algorithm and returns a <see cref="bool"/> value that determines whether the encryption was successful. All possible exceptions are caught.</summary>
        /// <typeparam name="TSource">The type of source.</typeparam>
        /// <param name="source">The object to encrypt.</param>
        /// <param name="hash">If successful, the result of encrypting the specified <paramref name="source"/> object by the <see cref="ChecksumAlgo.Sha256"/> algorithm; otherwise, <see langword="default"/>.</param>
        /// <returns><see langword="true"/> if the specified <paramref name="source"/> could be encrypted by the <see cref="ChecksumAlgo.Sha256"/> algorithm; otherwise, <see langword="false"/>.</returns>
        /// <inheritdoc cref="TryGetCipher{TSource}(TSource, ChecksumAlgo, out ulong)"/>
        public static bool TryGetCipher<TSource>(this TSource source, out ulong hash) =>
            source.TryGetCipher(ChecksumAlgo.Sha256, out hash);

        /// <inheritdoc cref="TryGetCipher{TSource}(TSource, ChecksumAlgo, out ulong)"/>
        public static bool TryGetChecksum<TSource>([NotNullWhen(true)] this TSource source, ChecksumAlgo algorithm, out string hash)
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
        public static bool TryGetChecksum<TSource>([NotNullWhen(true)] this TSource source, out string hash) =>
            source.TryGetChecksum(ChecksumAlgo.Sha256, out hash);

        /// <summary>Creates a default instance of this algorithm.</summary>
        /// <param name="algorithm">The algorithm to use.</param>
        /// <returns>A default instance of the specified algorithm.</returns>
        public static IChecksumAlgorithm GetDefaultInstance(this ChecksumAlgo algorithm) =>
            algorithm switch
            {
                ChecksumAlgo.Adler32 => new Adler32(),
                ChecksumAlgo.Crc16 => new Crc16(),
                ChecksumAlgo.Crc16A => new Crc16(Crc16Preset.A),
                ChecksumAlgo.Crc16Arc => new Crc16(Crc16Preset.Arc),
                ChecksumAlgo.Crc16AugCcitt => new Crc16(Crc16Preset.AugCcitt),
                ChecksumAlgo.Crc16Buypass => new Crc16(Crc16Preset.Buypass),
                ChecksumAlgo.Crc16CcittFalse => new Crc16(Crc16Preset.CcittFalse),
                ChecksumAlgo.Crc16Cdma2000 => new Crc16(Crc16Preset.Cdma2000),
                ChecksumAlgo.Crc16Dds110 => new Crc16(Crc16Preset.Dds110),
                ChecksumAlgo.Crc16DectR => new Crc16(Crc16Preset.DectR),
                ChecksumAlgo.Crc16DectX => new Crc16(Crc16Preset.DectX),
                ChecksumAlgo.Crc16Dnp => new Crc16(Crc16Preset.Dnp),
                ChecksumAlgo.Crc16En13757 => new Crc16(Crc16Preset.En13757),
                ChecksumAlgo.Crc16Genibus => new Crc16(Crc16Preset.Genibus),
                ChecksumAlgo.Crc16Kermit => new Crc16(Crc16Preset.Kermit),
                ChecksumAlgo.Crc16Maxim => new Crc16(Crc16Preset.Maxim),
                ChecksumAlgo.Crc16Mcrf4Xx => new Crc16(Crc16Preset.Mcrf4Xx),
                ChecksumAlgo.Crc16ModBus => new Crc16(Crc16Preset.ModBus),
                ChecksumAlgo.Crc16Riello => new Crc16(Crc16Preset.Riello),
                ChecksumAlgo.Crc16T10Dif => new Crc16(Crc16Preset.T10Dif),
                ChecksumAlgo.Crc16TeleDisk => new Crc16(Crc16Preset.TeleDisk),
                ChecksumAlgo.Crc16Tms37157 => new Crc16(Crc16Preset.Tms37157),
                ChecksumAlgo.Crc16XModem => new Crc16(Crc16Preset.A),
                ChecksumAlgo.Crc16X25 => new Crc16(Crc16Preset.X25),
                ChecksumAlgo.Crc17 => new Crc17(),
                ChecksumAlgo.Crc21 => new Crc21(),
                ChecksumAlgo.Crc24 => new Crc24(),
                ChecksumAlgo.Crc24Ble => new Crc24(Crc24Preset.Ble),
                ChecksumAlgo.Crc24LteA => new Crc24(Crc24Preset.LteA),
                ChecksumAlgo.Crc24LteB => new Crc24(Crc24Preset.LteB),
                ChecksumAlgo.Crc24FlexRayA => new Crc24(Crc24Preset.FlexRayA),
                ChecksumAlgo.Crc24FlexRayB => new Crc24(Crc24Preset.FlexRayB),
                ChecksumAlgo.Crc24Interlaken => new Crc24(Crc24Preset.Interlaken),
                ChecksumAlgo.Crc24Os9 => new Crc24(Crc24Preset.Os9),
                ChecksumAlgo.Crc30 => new Crc30(),
                ChecksumAlgo.Crc31 => new Crc31(),
                ChecksumAlgo.Crc32 => new Crc32(),
                ChecksumAlgo.Crc32Autosar => new Crc32(Crc32Preset.Autosar),
                ChecksumAlgo.Crc32CdRomEdc => new Crc32(Crc32Preset.CdRomEdc),
                ChecksumAlgo.Crc32Q => new Crc32(Crc32Preset.Q),
                ChecksumAlgo.Crc32BZip2 => new Crc32(Crc32Preset.BZip2),
                ChecksumAlgo.Crc32C => new Crc32(Crc32Preset.C),
                ChecksumAlgo.Crc32D => new Crc32(Crc32Preset.D),
                ChecksumAlgo.Crc32JamCrc => new Crc32(Crc32Preset.JamCrc),
                ChecksumAlgo.Crc32Mpeg2 => new Crc32(Crc32Preset.Mpeg2),
                ChecksumAlgo.Crc32Posix => new Crc32(Crc32Preset.Posix),
                ChecksumAlgo.Crc32Xfer => new Crc32(Crc32Preset.Xfer),
                ChecksumAlgo.Crc40 => new Crc40(),
                ChecksumAlgo.Crc64 => new Crc64(),
                ChecksumAlgo.Crc64We => new Crc64(Crc64Preset.We),
                ChecksumAlgo.Crc64Xz => new Crc64(Crc64Preset.Xz),
                ChecksumAlgo.Crc64GoIso => new Crc64(Crc64Preset.GoIso),
                ChecksumAlgo.Crc82 => new Crc82(),
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
    }
}
