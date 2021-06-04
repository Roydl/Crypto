﻿namespace Roydl.Crypto.Checksum
{
    using System;
    using System.Collections.Concurrent;
    using System.Collections.Generic;
    using System.IO;
    using System.Numerics;
    using Resources;

    /// <summary>Provides functions for loading instances to compute CRC hashes.</summary>
    public static class Crc
    {
        /// <summary>Initializes a new instance of the <see cref="Crc"/> class with the specified configuration preset.</summary>
        /// <param name="preset">The config preset.</param>
        /// <returns>A newly created <see cref="Crc"/> instance.</returns>
        public static Crc<byte> Create(CrcOptions.Crc preset) =>
            new(preset);

        /// <inheritdoc cref="Create(CrcOptions.Crc)"/>
        public static Crc<ushort> Create(CrcOptions.Crc10 preset) =>
            new(preset);

        /// <inheritdoc cref="Create(CrcOptions.Crc)"/>
        public static Crc<ushort> Create(CrcOptions.Crc11 preset) =>
            new(preset);

        /// <inheritdoc cref="Create(CrcOptions.Crc)"/>
        public static Crc<ushort> Create(CrcOptions.Crc12 preset) =>
            new(preset);

        /// <inheritdoc cref="Create(CrcOptions.Crc)"/>
        public static Crc<ushort> Create(CrcOptions.Crc13 preset) =>
            new(preset);

        /// <inheritdoc cref="Create(CrcOptions.Crc)"/>
        public static Crc<ushort> Create(CrcOptions.Crc14 preset) =>
            new(preset);

        /// <inheritdoc cref="Create(CrcOptions.Crc)"/>
        public static Crc<ushort> Create(CrcOptions.Crc15 preset) =>
            new(preset);

        /// <inheritdoc cref="Create(CrcOptions.Crc)"/>
        public static Crc<ushort> Create(CrcOptions.Crc16 preset) =>
            new(preset);

        /// <inheritdoc cref="Create(CrcOptions.Crc)"/>
        public static Crc<uint> Create(CrcOptions.Crc17 preset) =>
            new(preset);

        /// <inheritdoc cref="Create(CrcOptions.Crc)"/>
        public static Crc<uint> Create(CrcOptions.Crc21 preset) =>
            new(preset);

        /// <inheritdoc cref="Create(CrcOptions.Crc)"/>
        public static Crc<uint> Create(CrcOptions.Crc24 preset) =>
            new(preset);

        /// <inheritdoc cref="Create(CrcOptions.Crc)"/>
        public static Crc<uint> Create(CrcOptions.Crc30 preset) =>
            new(preset);

        /// <inheritdoc cref="Create(CrcOptions.Crc)"/>
        public static Crc<uint> Create(CrcOptions.Crc31 preset) =>
            new(preset);

        /// <inheritdoc cref="Create(CrcOptions.Crc)"/>
        public static Crc<uint> Create(CrcOptions.Crc32 preset) =>
            new(preset);

        /// <inheritdoc cref="Create(CrcOptions.Crc)"/>
        public static Crc<ulong> Create(CrcOptions.Crc40 preset) =>
            new(preset);

        /// <inheritdoc cref="Create(CrcOptions.Crc)"/>
        public static Crc<ulong> Create(CrcOptions.Crc64 preset) =>
            new(preset);

        /// <inheritdoc cref="Create(CrcOptions.Crc)"/>
        public static Crc<BigInteger> Create(CrcOptions.Crc82 preset) =>
            new(preset);
    }

    /// <summary>Provides functionality to compute CRC hashes.</summary>
    /// <remarks>Generic type usage:
    ///     <list type="bullet">
    ///         <item><term><see cref="byte"/></term> <description>CRC-8/<see cref="CrcOptions.Crc">Preset</see></description></item>
    ///         <item><term><see cref="ushort"/></term> <description>CRC-16/<see cref="CrcOptions.Crc16">Preset</see></description></item>
    ///         <item><term><see cref="uint"/></term> <description>CRC-32/<see cref="CrcOptions.Crc32">Preset</see></description></item>
    ///         <item><term><see cref="ulong"/></term> <description>CRC-64/<see cref="CrcOptions.Crc64">Preset</see></description></item>
    ///         <item><term><see cref="BigInteger"/></term> <description>CRC-82/<see cref="CrcOptions.Crc82">Preset</see></description></item>
    ///     </list>
    /// </remarks>
    /// <typeparam name="TValue">The integral type of the hash code. Must be <see cref="byte"/>, <see cref="ushort"/>, <see cref="uint"/>, <see cref="ulong"/>, or <see cref="BigInteger"/>.</typeparam>
    public sealed class Crc<TValue> : ChecksumAlgorithm<Crc<TValue>, TValue> where TValue : struct, IComparable, IFormattable
    {
        // ReSharper disable once StaticMemberInGenericType
        // We don't want the same CRC tables to be created multiple times.
        private static IDictionary<Enum, object> ConfigCache { get; } = new ConcurrentDictionary<Enum, object>();

        private ICrcConfig<TValue> Current { get; }

        /// <summary>Initializes a new instance of the <see cref="Crc{TValue}"/> class.</summary>
        /// <remarks>Generic type usage:
        ///     <list type="bullet">
        ///         <item><term><see cref="byte"/></term> <description>CRC-8/<see cref="CrcOptions.Crc.Default">Default</see></description></item>
        ///         <item><term><see cref="ushort"/></term> <description>CRC-16/<see cref="CrcOptions.Crc16.Default">Default</see></description></item>
        ///         <item><term><see cref="uint"/></term> <description>CRC-32/<see cref="CrcOptions.Crc32.Default">Default</see></description></item>
        ///         <item><term><see cref="ulong"/></term> <description>CRC-64/<see cref="CrcOptions.Crc64.Default">Default</see></description></item>
        ///         <item><term><see cref="BigInteger"/></term> <description>CRC-82/<see cref="CrcOptions.Crc82.Default">Default</see></description></item>
        ///     </list>
        /// </remarks>
        /// <exception cref="InvalidOperationException">TValue is invalid, i.e. not supported.</exception>
        public Crc() : base(GetBitsByType(default), GetStringHashSize(GetBitsByType(default))) =>
            Current = GetConfig(default, default);

        /// <summary>Initializes a new instance of the <see cref="Crc{TValue}"/> class.
        ///     <para>The generic type of the specified <paramref name="preset"/> must be <see cref="byte"/>.</para>
        /// </summary>
        /// <param name="preset">The config preset.</param>
        /// <exception cref="InvalidOperationException">TValue is invalid, i.e. not supported.</exception>
        public Crc(CrcOptions.Crc preset) : base(8) =>
            Current = GetConfig(8, preset);

        /// <summary>Initializes a new instance of the <see cref="Crc{TValue}"/> class.
        ///     <para>The generic type of the specified <paramref name="preset"/> must be <see cref="ushort"/>.</para>
        /// </summary>
        /// <inheritdoc cref="Crc{TValue}(CrcOptions.Crc)"/>
        public Crc(CrcOptions.Crc10 preset) : base(10, GetStringHashSize(10)) =>
            Current = GetConfig(10, preset);

        /// <inheritdoc cref="Crc{TValue}(CrcOptions.Crc10)"/>
        public Crc(CrcOptions.Crc11 preset) : base(11, GetStringHashSize(11)) =>
            Current = GetConfig(11, preset);

        /// <inheritdoc cref="Crc{TValue}(CrcOptions.Crc10)"/>
        public Crc(CrcOptions.Crc12 preset) : base(12, GetStringHashSize(12)) =>
            Current = GetConfig(12, preset);

        /// <inheritdoc cref="Crc{TValue}(CrcOptions.Crc10)"/>
        public Crc(CrcOptions.Crc13 preset) : base(13) =>
            Current = GetConfig(13, preset);

        /// <inheritdoc cref="Crc{TValue}(CrcOptions.Crc10)"/>
        public Crc(CrcOptions.Crc14 preset) : base(14) =>
            Current = GetConfig(14, preset);

        /// <inheritdoc cref="Crc{TValue}(CrcOptions.Crc10)"/>
        public Crc(CrcOptions.Crc15 preset) : base(15) =>
            Current = GetConfig(15, preset);

        /// <inheritdoc cref="Crc{TValue}(CrcOptions.Crc10)"/>
        public Crc(CrcOptions.Crc16 preset) : base(16) =>
            Current = GetConfig(16, preset);

        /// <summary>Initializes a new instance of the <see cref="Crc{TValue}"/> class.
        ///     <para>The generic type of the specified <paramref name="preset"/> must be <see cref="uint"/>.</para>
        /// </summary>
        /// <inheritdoc cref="Crc{TValue}(CrcOptions.Crc)"/>
        public Crc(CrcOptions.Crc17 preset) : base(17, GetStringHashSize(17)) =>
            Current = GetConfig(17, preset);

        /// <inheritdoc cref="Crc{TValue}(CrcOptions.Crc17)"/>
        public Crc(CrcOptions.Crc21 preset) : base(21) =>
            Current = GetConfig(21, preset);

        /// <inheritdoc cref="Crc{TValue}(CrcOptions.Crc17)"/>
        public Crc(CrcOptions.Crc24 preset) : base(24) =>
            Current = GetConfig(24, preset);

        /// <inheritdoc cref="Crc{TValue}(CrcOptions.Crc17)"/>
        public Crc(CrcOptions.Crc30 preset) : base(30) =>
            Current = GetConfig(30, preset);

        /// <inheritdoc cref="Crc{TValue}(CrcOptions.Crc17)"/>
        public Crc(CrcOptions.Crc31 preset) : base(31) =>
            Current = GetConfig(31, preset);

        /// <inheritdoc cref="Crc{TValue}(CrcOptions.Crc17)"/>
        public Crc(CrcOptions.Crc32 preset) : base(32) =>
            Current = GetConfig(32, preset);

        /// <summary>Initializes a new instance of the <see cref="Crc{TValue}"/> class.
        ///     <para>The generic type of the specified <paramref name="preset"/> must be <see cref="ulong"/>.</para>
        /// </summary>
        /// <inheritdoc cref="Crc{TValue}(CrcOptions.Crc)"/>
        public Crc(CrcOptions.Crc40 preset) : base(40) =>
            Current = GetConfig(40, preset);

        /// <inheritdoc cref="Crc{TValue}(CrcOptions.Crc40)"/>
        public Crc(CrcOptions.Crc64 preset) : base(64) =>
            Current = GetConfig(64, preset);

        /// <summary>Initializes a new instance of the <see cref="Crc{TValue}"/> class.
        ///     <para>The generic type of the specified <paramref name="preset"/> must be <see cref="BigInteger"/>.</para>
        /// </summary>
        /// <inheritdoc cref="Crc{TValue}(CrcOptions.Crc)"/>
        public Crc(CrcOptions.Crc82 preset) : base(82, GetStringHashSize(82)) =>
            Current = GetConfig(82, preset);

        /// <summary>Initializes a new instance of the <see cref="Crc{TValue}"/> class.</summary>
        /// <param name="config">The CRC config.</param>
        /// <exception cref="InvalidOperationException">TValue is invalid, i.e. not supported.</exception>
        public Crc(ICrcConfig<TValue> config) : base(config.Bits, GetStringHashSize(config.Bits))
        {
            switch (default(TValue))
            {
                case byte:
                case ushort:
                case uint:
                case ulong:
                case BigInteger:
                    break;
                default:
                    throw new InvalidOperationException(ExceptionMessages.InvalidOperationUnsupportedType);
            }
            Current = config;
        }

        /// <summary>Initializes a new instance of the <see cref="Crc{TValue}"/> class and encrypts the specified stream.</summary>
        /// <inheritdoc cref="Crc{TValue}()"/>
        /// <inheritdoc cref="IChecksumAlgorithm.Encrypt(Stream)"/>
        public Crc(Stream stream) : this() =>
            Encrypt(stream);

        /// <summary>Initializes a new instance of the <see cref="Crc{TValue}"/> class and encrypts the specified sequence of bytes.</summary>
        /// <inheritdoc cref="Crc{TValue}()"/>
        /// <inheritdoc cref="ChecksumAlgorithm(int, byte[])"/>
        public Crc(byte[] bytes) : this() =>
            Encrypt(bytes);

        /// <summary>Initializes a new instance of the <see cref="Crc{TValue}"/> class and encrypts the specified text or file.</summary>
        /// <inheritdoc cref="Crc{TValue}()"/>
        /// <inheritdoc cref="ChecksumAlgorithm(int, string, bool)"/>
        public Crc(string textOrFile, bool strIsFilePath) : this() =>
            Encrypt(textOrFile, strIsFilePath);

        /// <summary>Initializes a new instance of the <see cref="Crc{TValue}"/> class and encrypts the specified text.</summary>
        /// <inheritdoc cref="Crc{TValue}()"/>
        /// <inheritdoc cref="ChecksumAlgorithm(int, string)"/>
        public Crc(string text) : this() =>
            Encrypt(text);

        /// <summary>Initializes a new instance of the <see cref="Crc{TValue}"/> class and encrypts the specified file.</summary>
        /// <inheritdoc cref="Crc{TValue}()"/>
        /// <inheritdoc cref="ChecksumAlgorithm(int, FileInfo)"/>
        public Crc(FileInfo fileInfo) : this() =>
            Encrypt(fileInfo);

        /// <inheritdoc/>
        public override void Encrypt(Stream stream)
        {
            if (stream == null)
                throw new ArgumentNullException(nameof(stream));
            Current.ComputeHash(stream, out var num);
            HashNumber = num;
            RawHash = num switch
            {
                byte x => CryptoUtils.GetByteArray(x, RawHashSize),
                ushort x => CryptoUtils.GetByteArray(x, RawHashSize),
                uint x => CryptoUtils.GetByteArray(x, RawHashSize),
                ulong x => CryptoUtils.GetByteArray(x, RawHashSize),
                BigInteger x => x.ToByteArray(true, BitConverter.IsLittleEndian),
                _ => throw new InvalidOperationException(ExceptionMessages.InvalidOperationUnsupportedType)
            };
        }

        private static ICrcConfig<TValue> GetConfig(int bits, Enum preset)
        {
            var config = bits switch
            {
                08 => ConfigCache.TryGetValue(preset, out var x) ? x : ConfigCache[preset] = CrcConfigManager.GetConfig((CrcOptions.Crc)preset),
                10 => ConfigCache.TryGetValue(preset, out var x) ? x : ConfigCache[preset] = CrcConfigManager.GetConfig((CrcOptions.Crc10)preset),
                11 => ConfigCache.TryGetValue(preset, out var x) ? x : ConfigCache[preset] = CrcConfigManager.GetConfig((CrcOptions.Crc11)preset),
                12 => ConfigCache.TryGetValue(preset, out var x) ? x : ConfigCache[preset] = CrcConfigManager.GetConfig((CrcOptions.Crc12)preset),
                13 => ConfigCache.TryGetValue(preset, out var x) ? x : ConfigCache[preset] = CrcConfigManager.GetConfig((CrcOptions.Crc13)preset),
                14 => ConfigCache.TryGetValue(preset, out var x) ? x : ConfigCache[preset] = CrcConfigManager.GetConfig((CrcOptions.Crc14)preset),
                15 => ConfigCache.TryGetValue(preset, out var x) ? x : ConfigCache[preset] = CrcConfigManager.GetConfig((CrcOptions.Crc15)preset),
                16 => ConfigCache.TryGetValue(preset, out var x) ? x : ConfigCache[preset] = CrcConfigManager.GetConfig((CrcOptions.Crc16)preset),
                17 => ConfigCache.TryGetValue(preset, out var x) ? x : ConfigCache[preset] = CrcConfigManager.GetConfig((CrcOptions.Crc17)preset),
                21 => ConfigCache.TryGetValue(preset, out var x) ? x : ConfigCache[preset] = CrcConfigManager.GetConfig((CrcOptions.Crc21)preset),
                24 => ConfigCache.TryGetValue(preset, out var x) ? x : ConfigCache[preset] = CrcConfigManager.GetConfig((CrcOptions.Crc24)preset),
                30 => ConfigCache.TryGetValue(preset, out var x) ? x : ConfigCache[preset] = CrcConfigManager.GetConfig((CrcOptions.Crc30)preset),
                31 => ConfigCache.TryGetValue(preset, out var x) ? x : ConfigCache[preset] = CrcConfigManager.GetConfig((CrcOptions.Crc31)preset),
                32 => ConfigCache.TryGetValue(preset, out var x) ? x : ConfigCache[preset] = CrcConfigManager.GetConfig((CrcOptions.Crc32)preset),
                40 => ConfigCache.TryGetValue(preset, out var x) ? x : ConfigCache[preset] = CrcConfigManager.GetConfig((CrcOptions.Crc40)preset),
                64 => ConfigCache.TryGetValue(preset, out var x) ? x : ConfigCache[preset] = CrcConfigManager.GetConfig((CrcOptions.Crc64)preset),
                82 => ConfigCache.TryGetValue(preset, out var x) ? x : ConfigCache[preset] = CrcConfigManager.GetConfig((CrcOptions.Crc82)preset),
                _ => default(TValue) switch
                {
                    byte => ConfigCache.TryGetValue(CrcOptions.Crc.Default, out var x) ? x : ConfigCache[CrcOptions.Crc.Default] = CrcConfigManager.GetConfig(CrcOptions.Crc.Default),
                    ushort => ConfigCache.TryGetValue(CrcOptions.Crc16.Default, out var x) ? x : ConfigCache[CrcOptions.Crc16.Default] = CrcConfigManager.GetConfig(CrcOptions.Crc16.Default),
                    uint => ConfigCache.TryGetValue(CrcOptions.Crc32.Default, out var x) ? x : ConfigCache[CrcOptions.Crc32.Default] = CrcConfigManager.GetConfig(CrcOptions.Crc32.Default),
                    ulong => ConfigCache.TryGetValue(CrcOptions.Crc64.Default, out var x) ? x : ConfigCache[CrcOptions.Crc64.Default] = CrcConfigManager.GetConfig(CrcOptions.Crc64.Default),
                    BigInteger => ConfigCache.TryGetValue(CrcOptions.Crc82.Default, out var x) ? x : ConfigCache[CrcOptions.Crc82.Default] = CrcConfigManager.GetConfig(CrcOptions.Crc82.Default),
                    _ => throw new InvalidOperationException(ExceptionMessages.InvalidOperationUnsupportedType)
                }
            };
            return (ICrcConfig<TValue>)config;
        }

        private static int GetBitsByType(TValue value) =>
            value switch
            {
                byte => 8,
                ushort => 16,
                uint => 32,
                ulong => 64,
                BigInteger => 82,
                _ => throw new InvalidOperationException(ExceptionMessages.InvalidOperationUnsupportedType)
            };

        private static int GetStringHashSize(int bits)
        {
            switch (bits)
            {
                case 10:
                case 11:
                case 12:
                    return 3;
                case 17:
                    return 5;
                case 82:
                    return 21;
                default:
                    return default;
            }
        }
    }
}