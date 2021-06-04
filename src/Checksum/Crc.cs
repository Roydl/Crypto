namespace Roydl.Crypto.Checksum
{
    using System;
    using System.Collections.Concurrent;
    using System.Collections.Generic;
    using System.IO;
    using System.Numerics;
    using Resources;

    /// <summary>Provides functionality to compute CRC hashes.</summary>
    /// <remarks>Generic type usage:
    ///     <list type="bullet">
    ///         <item><term><see cref="byte"/></term> <description>CRC-8/<see cref="Crc08Preset.Default">Default</see></description></item>
    ///         <item><term><see cref="ushort"/></term> <description>CRC-16/<see cref="Crc16Preset.Default">Default</see></description></item>
    ///         <item><term><see cref="uint"/></term> <description>CRC-32/<see cref="Crc32Preset.Default">Default</see></description></item>
    ///         <item><term><see cref="ulong"/></term> <description>CRC-64/<see cref="Crc64Preset.Default">Default</see></description></item>
    ///         <item><term><see cref="BigInteger"/></term> <description>CRC-82/<see cref="Crc82Preset.Default">Default</see></description></item>
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
        /// <exception cref="InvalidOperationException">TValue is invalid, i.e. not supported.</exception>
        /// <inheritdoc cref="Crc{TValue}"/>
        public Crc() : base(GetBitsByType(default), GetStringHashSize(GetBitsByType(default))) =>
            Current = GetConfig(default, default);

        /// <summary>Initializes a new instance of the <see cref="Crc{TValue}"/> class.
        ///     <para>The generic type of the specified <paramref name="preset"/> must be <see cref="byte"/>.</para>
        /// </summary>
        /// <param name="preset">The config preset.</param>
        /// <exception cref="InvalidOperationException">TValue is invalid, i.e. not supported.</exception>
        public Crc(Crc08Preset preset) : base(8) =>
            Current = GetConfig(8, preset);

        /// <summary>Initializes a new instance of the <see cref="Crc{TValue}"/> class.
        ///     <para>The generic type of the specified <paramref name="preset"/> must be <see cref="ushort"/>.</para>
        /// </summary>
        /// <inheritdoc cref="Crc{TValue}(Crc08Preset)"/>
        public Crc(Crc10Preset preset) : base(10, GetStringHashSize(10)) =>
            Current = GetConfig(10, preset);

        /// <inheritdoc cref="Crc{TValue}(Crc10Preset)"/>
        public Crc(Crc11Preset preset) : base(11, GetStringHashSize(11)) =>
            Current = GetConfig(11, preset);

        /// <inheritdoc cref="Crc{TValue}(Crc10Preset)"/>
        public Crc(Crc12Preset preset) : base(12, GetStringHashSize(12)) =>
            Current = GetConfig(12, preset);

        /// <inheritdoc cref="Crc{TValue}(Crc10Preset)"/>
        public Crc(Crc13Preset preset) : base(13) =>
            Current = GetConfig(13, preset);

        /// <inheritdoc cref="Crc{TValue}(Crc10Preset)"/>
        public Crc(Crc14Preset preset) : base(14) =>
            Current = GetConfig(14, preset);

        /// <inheritdoc cref="Crc{TValue}(Crc10Preset)"/>
        public Crc(Crc15Preset preset) : base(15) =>
            Current = GetConfig(15, preset);

        /// <inheritdoc cref="Crc{TValue}(Crc10Preset)"/>
        public Crc(Crc16Preset preset) : base(16) =>
            Current = GetConfig(16, preset);

        /// <summary>Initializes a new instance of the <see cref="Crc{TValue}"/> class.
        ///     <para>The generic type of the specified <paramref name="preset"/> must be <see cref="uint"/>.</para>
        /// </summary>
        /// <inheritdoc cref="Crc{TValue}(Crc08Preset)"/>
        public Crc(Crc17Preset preset) : base(17, GetStringHashSize(17)) =>
            Current = GetConfig(17, preset);

        /// <inheritdoc cref="Crc{TValue}(Crc17Preset)"/>
        public Crc(Crc21Preset preset) : base(21) =>
            Current = GetConfig(21, preset);

        /// <inheritdoc cref="Crc{TValue}(Crc17Preset)"/>
        public Crc(Crc24Preset preset) : base(24) =>
            Current = GetConfig(24, preset);

        /// <inheritdoc cref="Crc{TValue}(Crc17Preset)"/>
        public Crc(Crc30Preset preset) : base(30) =>
            Current = GetConfig(30, preset);

        /// <inheritdoc cref="Crc{TValue}(Crc17Preset)"/>
        public Crc(Crc31Preset preset) : base(31) =>
            Current = GetConfig(31, preset);

        /// <inheritdoc cref="Crc{TValue}(Crc17Preset)"/>
        public Crc(Crc32Preset preset) : base(32) =>
            Current = GetConfig(32, preset);

        /// <summary>Initializes a new instance of the <see cref="Crc{TValue}"/> class.
        ///     <para>The generic type of the specified <paramref name="preset"/> must be <see cref="ulong"/>.</para>
        /// </summary>
        /// <inheritdoc cref="Crc{TValue}(Crc08Preset)"/>
        public Crc(Crc40Preset preset) : base(40) =>
            Current = GetConfig(40, preset);

        /// <inheritdoc cref="Crc{TValue}(Crc40Preset)"/>
        public Crc(Crc64Preset preset) : base(64) =>
            Current = GetConfig(64, preset);

        /// <summary>Initializes a new instance of the <see cref="Crc{TValue}"/> class.
        ///     <para>The generic type of the specified <paramref name="preset"/> must be <see cref="BigInteger"/>.</para>
        /// </summary>
        /// <inheritdoc cref="Crc{TValue}(Crc08Preset)"/>
        public Crc(Crc82Preset preset) : base(82, GetStringHashSize(82)) =>
            Current = GetConfig(82, preset);

        /// <summary>Initializes a new instance of the <see cref="Crc{TValue}"/> class.</summary>
        /// <param name="config">The CRC config.</param>
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
                08 => ConfigCache.TryGetValue(preset, out var x) ? x : ConfigCache[preset] = CrcPreset.GetConfig((Crc08Preset)preset),
                10 => ConfigCache.TryGetValue(preset, out var x) ? x : ConfigCache[preset] = CrcPreset.GetConfig((Crc10Preset)preset),
                11 => ConfigCache.TryGetValue(preset, out var x) ? x : ConfigCache[preset] = CrcPreset.GetConfig((Crc11Preset)preset),
                12 => ConfigCache.TryGetValue(preset, out var x) ? x : ConfigCache[preset] = CrcPreset.GetConfig((Crc12Preset)preset),
                13 => ConfigCache.TryGetValue(preset, out var x) ? x : ConfigCache[preset] = CrcPreset.GetConfig((Crc13Preset)preset),
                14 => ConfigCache.TryGetValue(preset, out var x) ? x : ConfigCache[preset] = CrcPreset.GetConfig((Crc14Preset)preset),
                15 => ConfigCache.TryGetValue(preset, out var x) ? x : ConfigCache[preset] = CrcPreset.GetConfig((Crc15Preset)preset),
                16 => ConfigCache.TryGetValue(preset, out var x) ? x : ConfigCache[preset] = CrcPreset.GetConfig((Crc16Preset)preset),
                17 => ConfigCache.TryGetValue(preset, out var x) ? x : ConfigCache[preset] = CrcPreset.GetConfig((Crc17Preset)preset),
                21 => ConfigCache.TryGetValue(preset, out var x) ? x : ConfigCache[preset] = CrcPreset.GetConfig((Crc21Preset)preset),
                24 => ConfigCache.TryGetValue(preset, out var x) ? x : ConfigCache[preset] = CrcPreset.GetConfig((Crc24Preset)preset),
                30 => ConfigCache.TryGetValue(preset, out var x) ? x : ConfigCache[preset] = CrcPreset.GetConfig((Crc30Preset)preset),
                31 => ConfigCache.TryGetValue(preset, out var x) ? x : ConfigCache[preset] = CrcPreset.GetConfig((Crc31Preset)preset),
                32 => ConfigCache.TryGetValue(preset, out var x) ? x : ConfigCache[preset] = CrcPreset.GetConfig((Crc32Preset)preset),
                40 => ConfigCache.TryGetValue(preset, out var x) ? x : ConfigCache[preset] = CrcPreset.GetConfig((Crc40Preset)preset),
                64 => ConfigCache.TryGetValue(preset, out var x) ? x : ConfigCache[preset] = CrcPreset.GetConfig((Crc64Preset)preset),
                82 => ConfigCache.TryGetValue(preset, out var x) ? x : ConfigCache[preset] = CrcPreset.GetConfig((Crc82Preset)preset),
                _ => default(TValue) switch
                {
                    byte => ConfigCache.TryGetValue(Crc08Preset.Default, out var x) ? x : ConfigCache[Crc08Preset.Default] = CrcPreset.GetConfig(Crc08Preset.Default),
                    ushort => ConfigCache.TryGetValue(Crc16Preset.Default, out var x) ? x : ConfigCache[Crc16Preset.Default] = CrcPreset.GetConfig(Crc16Preset.Default),
                    uint => ConfigCache.TryGetValue(Crc32Preset.Default, out var x) ? x : ConfigCache[Crc32Preset.Default] = CrcPreset.GetConfig(Crc32Preset.Default),
                    ulong => ConfigCache.TryGetValue(Crc64Preset.Default, out var x) ? x : ConfigCache[Crc64Preset.Default] = CrcPreset.GetConfig(Crc64Preset.Default),
                    BigInteger => ConfigCache.TryGetValue(Crc82Preset.Default, out var x) ? x : ConfigCache[Crc82Preset.Default] = CrcPreset.GetConfig(Crc82Preset.Default),
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
