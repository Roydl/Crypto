namespace Roydl.Crypto.Checksum
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
        public static Crc<byte> Create(CrcOptions.Crc preset) => new(preset);

        /// <inheritdoc cref="Create(CrcOptions.Crc)"/>
        public static Crc<ushort> Create(CrcOptions.Crc10 preset) => new(preset);

        /// <inheritdoc cref="Create(CrcOptions.Crc)"/>
        public static Crc<ushort> Create(CrcOptions.Crc11 preset) => new(preset);

        /// <inheritdoc cref="Create(CrcOptions.Crc)"/>
        public static Crc<ushort> Create(CrcOptions.Crc12 preset) => new(preset);

        /// <inheritdoc cref="Create(CrcOptions.Crc)"/>
        public static Crc<ushort> Create(CrcOptions.Crc13 preset) => new(preset);

        /// <inheritdoc cref="Create(CrcOptions.Crc)"/>
        public static Crc<ushort> Create(CrcOptions.Crc14 preset) => new(preset);

        /// <inheritdoc cref="Create(CrcOptions.Crc)"/>
        public static Crc<ushort> Create(CrcOptions.Crc15 preset) => new(preset);

        /// <inheritdoc cref="Create(CrcOptions.Crc)"/>
        public static Crc<ushort> Create(CrcOptions.Crc16 preset) => new(preset);

        /// <inheritdoc cref="Create(CrcOptions.Crc)"/>
        public static Crc<uint> Create(CrcOptions.Crc17 preset) => new(preset);

        /// <inheritdoc cref="Create(CrcOptions.Crc)"/>
        public static Crc<uint> Create(CrcOptions.Crc21 preset) => new(preset);

        /// <inheritdoc cref="Create(CrcOptions.Crc)"/>
        public static Crc<uint> Create(CrcOptions.Crc24 preset) => new(preset);

        /// <inheritdoc cref="Create(CrcOptions.Crc)"/>
        public static Crc<uint> Create(CrcOptions.Crc30 preset) => new(preset);

        /// <inheritdoc cref="Create(CrcOptions.Crc)"/>
        public static Crc<uint> Create(CrcOptions.Crc31 preset) => new(preset);

        /// <inheritdoc cref="Create(CrcOptions.Crc)"/>
        public static Crc<uint> Create(CrcOptions.Crc32 preset) => new(preset);

        /// <inheritdoc cref="Create(CrcOptions.Crc)"/>
        public static Crc<ulong> Create(CrcOptions.Crc40 preset) => new(preset);

        /// <inheritdoc cref="Create(CrcOptions.Crc)"/>
        public static Crc<ulong> Create(CrcOptions.Crc64 preset) => new(preset);

        /// <inheritdoc cref="Create(CrcOptions.Crc)"/>
        public static Crc<BigInteger> Create(CrcOptions.Crc82 preset) => new(preset);
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
        public Crc() : base(GetBitWidth(), GetStringSize(GetBitWidth())) =>
            Current = GetConfig();

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
        public Crc(CrcOptions.Crc10 preset) : base(10, GetStringSize(10)) =>
            Current = GetConfig(10, preset);

        /// <inheritdoc cref="Crc{TValue}(CrcOptions.Crc10)"/>
        public Crc(CrcOptions.Crc11 preset) : base(11, GetStringSize(11)) =>
            Current = GetConfig(11, preset);

        /// <inheritdoc cref="Crc{TValue}(CrcOptions.Crc10)"/>
        public Crc(CrcOptions.Crc12 preset) : base(12, GetStringSize(12)) =>
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
        public Crc(CrcOptions.Crc17 preset) : base(17, GetStringSize(17)) =>
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
        public Crc(CrcOptions.Crc82 preset) : base(82, GetStringSize(82)) =>
            Current = GetConfig(82, preset);

        /// <summary>Initializes a new instance of the <see cref="Crc{TValue}"/> class.</summary>
        /// <param name="config">The CRC config.</param>
        /// <exception cref="InvalidOperationException">TValue is invalid, i.e. not supported.</exception>
        public Crc(ICrcConfig<TValue> config) : base(config.BitWidth, GetStringSize(config.BitWidth))
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

        /// <inheritdoc/>
        public override void Encrypt(Stream stream)
        {
            Reset();
            if (stream == null)
                throw new ArgumentNullException(nameof(stream));
            Current.ComputeHash(stream, out var sum);
            FinalizeHash(sum);
        }

        /// <inheritdoc/>
        public override void Encrypt(ReadOnlySpan<byte> bytes)
        {
            Reset();
            if (bytes == null)
                throw new ArgumentNullException(nameof(bytes));
            if (bytes.Length < 1)
                throw new ArgumentException(ExceptionMessages.ArgumentEmpty, nameof(bytes));
            Current.ComputeHash(bytes, out var sum);
            FinalizeHash(sum);
        }

        private static int GetBitWidth() =>
            default(TValue) switch
            {
                byte => 8,
                ushort => 16,
                uint => 32,
                ulong => 64,
                BigInteger => 82,
                _ => throw new InvalidOperationException(ExceptionMessages.InvalidOperationUnsupportedType)
            };

        private static int GetStringSize(int bitWidth)
        {
            switch (bitWidth)
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

        private static ICrcConfig<TValue> GetConfig()
        {
            var cc = ConfigCache;
            var cfg = default(TValue) switch
            {
                byte => cc.TryGetValue(CrcOptions.Crc.Default, out var x) ? x : cc[CrcOptions.Crc.Default] = CrcConfigManager.GetConfig(CrcOptions.Crc.Default),
                ushort => cc.TryGetValue(CrcOptions.Crc16.Default, out var x) ? x : cc[CrcOptions.Crc16.Default] = CrcConfigManager.GetConfig(CrcOptions.Crc16.Default),
                uint => cc.TryGetValue(CrcOptions.Crc32.Default, out var x) ? x : cc[CrcOptions.Crc32.Default] = CrcConfigManager.GetConfig(CrcOptions.Crc32.Default),
                ulong => cc.TryGetValue(CrcOptions.Crc64.Default, out var x) ? x : cc[CrcOptions.Crc64.Default] = CrcConfigManager.GetConfig(CrcOptions.Crc64.Default),
                BigInteger => cc.TryGetValue(CrcOptions.Crc82.Default, out var x) ? x : cc[CrcOptions.Crc82.Default] = CrcConfigManager.GetConfig(CrcOptions.Crc82.Default),
                _ => throw new InvalidOperationException(ExceptionMessages.InvalidOperationUnsupportedType)
            };
            return (ICrcConfig<TValue>)cfg;
        }

        private static ICrcConfig<TValue> GetConfig(int bitWidth, Enum preset)
        {
            var cc = ConfigCache;
            var cfg = bitWidth switch
            {
                8 => cc.TryGetValue(preset, out var x) ? x : cc[preset] = CrcConfigManager.GetConfig((CrcOptions.Crc)preset),
                10 => cc.TryGetValue(preset, out var x) ? x : cc[preset] = CrcConfigManager.GetConfig((CrcOptions.Crc10)preset),
                11 => cc.TryGetValue(preset, out var x) ? x : cc[preset] = CrcConfigManager.GetConfig((CrcOptions.Crc11)preset),
                12 => cc.TryGetValue(preset, out var x) ? x : cc[preset] = CrcConfigManager.GetConfig((CrcOptions.Crc12)preset),
                13 => cc.TryGetValue(preset, out var x) ? x : cc[preset] = CrcConfigManager.GetConfig((CrcOptions.Crc13)preset),
                14 => cc.TryGetValue(preset, out var x) ? x : cc[preset] = CrcConfigManager.GetConfig((CrcOptions.Crc14)preset),
                15 => cc.TryGetValue(preset, out var x) ? x : cc[preset] = CrcConfigManager.GetConfig((CrcOptions.Crc15)preset),
                16 => cc.TryGetValue(preset, out var x) ? x : cc[preset] = CrcConfigManager.GetConfig((CrcOptions.Crc16)preset),
                17 => cc.TryGetValue(preset, out var x) ? x : cc[preset] = CrcConfigManager.GetConfig((CrcOptions.Crc17)preset),
                21 => cc.TryGetValue(preset, out var x) ? x : cc[preset] = CrcConfigManager.GetConfig((CrcOptions.Crc21)preset),
                24 => cc.TryGetValue(preset, out var x) ? x : cc[preset] = CrcConfigManager.GetConfig((CrcOptions.Crc24)preset),
                30 => cc.TryGetValue(preset, out var x) ? x : cc[preset] = CrcConfigManager.GetConfig((CrcOptions.Crc30)preset),
                31 => cc.TryGetValue(preset, out var x) ? x : cc[preset] = CrcConfigManager.GetConfig((CrcOptions.Crc31)preset),
                32 => cc.TryGetValue(preset, out var x) ? x : cc[preset] = CrcConfigManager.GetConfig((CrcOptions.Crc32)preset),
                40 => cc.TryGetValue(preset, out var x) ? x : cc[preset] = CrcConfigManager.GetConfig((CrcOptions.Crc40)preset),
                64 => cc.TryGetValue(preset, out var x) ? x : cc[preset] = CrcConfigManager.GetConfig((CrcOptions.Crc64)preset),
                82 => cc.TryGetValue(preset, out var x) ? x : cc[preset] = CrcConfigManager.GetConfig((CrcOptions.Crc82)preset),
                _ => GetConfig()
            };
            return (ICrcConfig<TValue>)cfg;
        }

        private void FinalizeHash(TValue hash)
        {
            HashNumber = hash;
            RawHash = CryptoUtils.GetByteArray(hash, !BitConverter.IsLittleEndian);
        }
    }
}
