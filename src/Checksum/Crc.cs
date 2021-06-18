namespace Roydl.Crypto.Checksum
{
    using System;
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
            Current = ValidateConfig(default);

        /// <summary>Initializes a new instance of the <see cref="Crc{TValue}"/> class.
        ///     <para>The generic type of the specified <paramref name="preset"/> must be <see cref="byte"/>.</para>
        /// </summary>
        /// <param name="preset">The config preset.</param>
        /// <exception cref="InvalidOperationException">TValue is invalid, i.e. not supported.</exception>
        public Crc(CrcOptions.Crc preset) : base(8) =>
            Current = ValidateConfig(preset);

        /// <summary>Initializes a new instance of the <see cref="Crc{TValue}"/> class.
        ///     <para>The generic type of the specified <paramref name="preset"/> must be <see cref="ushort"/>.</para>
        /// </summary>
        /// <inheritdoc cref="Crc{TValue}(CrcOptions.Crc)"/>
        public Crc(CrcOptions.Crc10 preset) : base(10, GetStringSize(10)) =>
            Current = ValidateConfig(preset);

        /// <inheritdoc cref="Crc{TValue}(CrcOptions.Crc10)"/>
        public Crc(CrcOptions.Crc11 preset) : base(11, GetStringSize(11)) =>
            Current = ValidateConfig(preset);

        /// <inheritdoc cref="Crc{TValue}(CrcOptions.Crc10)"/>
        public Crc(CrcOptions.Crc12 preset) : base(12, GetStringSize(12)) =>
            Current = ValidateConfig(preset);

        /// <inheritdoc cref="Crc{TValue}(CrcOptions.Crc10)"/>
        public Crc(CrcOptions.Crc13 preset) : base(13) =>
            Current = ValidateConfig(preset);

        /// <inheritdoc cref="Crc{TValue}(CrcOptions.Crc10)"/>
        public Crc(CrcOptions.Crc14 preset) : base(14) =>
            Current = ValidateConfig(preset);

        /// <inheritdoc cref="Crc{TValue}(CrcOptions.Crc10)"/>
        public Crc(CrcOptions.Crc15 preset) : base(15) =>
            Current = ValidateConfig(preset);

        /// <inheritdoc cref="Crc{TValue}(CrcOptions.Crc10)"/>
        public Crc(CrcOptions.Crc16 preset) : base(16) =>
            Current = ValidateConfig(preset);

        /// <summary>Initializes a new instance of the <see cref="Crc{TValue}"/> class.
        ///     <para>The generic type of the specified <paramref name="preset"/> must be <see cref="uint"/>.</para>
        /// </summary>
        /// <inheritdoc cref="Crc{TValue}(CrcOptions.Crc)"/>
        public Crc(CrcOptions.Crc17 preset) : base(17, GetStringSize(17)) =>
            Current = ValidateConfig(preset);

        /// <inheritdoc cref="Crc{TValue}(CrcOptions.Crc17)"/>
        public Crc(CrcOptions.Crc21 preset) : base(21) =>
            Current = ValidateConfig(preset);

        /// <inheritdoc cref="Crc{TValue}(CrcOptions.Crc17)"/>
        public Crc(CrcOptions.Crc24 preset) : base(24) =>
            Current = ValidateConfig(preset);

        /// <inheritdoc cref="Crc{TValue}(CrcOptions.Crc17)"/>
        public Crc(CrcOptions.Crc30 preset) : base(30) =>
            Current = ValidateConfig(preset);

        /// <inheritdoc cref="Crc{TValue}(CrcOptions.Crc17)"/>
        public Crc(CrcOptions.Crc31 preset) : base(31) =>
            Current = ValidateConfig(preset);

        /// <inheritdoc cref="Crc{TValue}(CrcOptions.Crc17)"/>
        public Crc(CrcOptions.Crc32 preset) : base(32) =>
            Current = ValidateConfig(preset);

        /// <summary>Initializes a new instance of the <see cref="Crc{TValue}"/> class.
        ///     <para>The generic type of the specified <paramref name="preset"/> must be <see cref="ulong"/>.</para>
        /// </summary>
        /// <inheritdoc cref="Crc{TValue}(CrcOptions.Crc)"/>
        public Crc(CrcOptions.Crc40 preset) : base(40) =>
            Current = ValidateConfig(preset);

        /// <inheritdoc cref="Crc{TValue}(CrcOptions.Crc40)"/>
        public Crc(CrcOptions.Crc64 preset) : base(64) =>
            Current = ValidateConfig(preset);

        /// <summary>Initializes a new instance of the <see cref="Crc{TValue}"/> class.
        ///     <para>The generic type of the specified <paramref name="preset"/> must be <see cref="BigInteger"/>.</para>
        /// </summary>
        /// <inheritdoc cref="Crc{TValue}(CrcOptions.Crc)"/>
        public Crc(CrcOptions.Crc82 preset) : base(82, GetStringSize(82)) =>
            Current = ValidateConfig(preset);

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
        public override void ComputeHash(Stream stream)
        {
            Reset();
            if (stream == null)
                throw new ArgumentNullException(nameof(stream));
            Current.ComputeHash(stream, out var sum);
            Update(sum);
        }

        /// <inheritdoc/>
        public override void ComputeHash(ReadOnlySpan<byte> bytes)
        {
            Reset();
            if (bytes.IsEmpty)
                throw new ArgumentException(ExceptionMessages.ArgumentEmpty, nameof(bytes));
            Current.ComputeHash(bytes, out var sum);
            Update(sum);
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

        private static string GetName(Enum preset)
        {
            var width = preset switch
            {
                CrcOptions.Crc => 8,
                CrcOptions.Crc10 => 10,
                CrcOptions.Crc11 => 11,
                CrcOptions.Crc12 => 12,
                CrcOptions.Crc13 => 13,
                CrcOptions.Crc14 => 14,
                CrcOptions.Crc15 => 15,
                CrcOptions.Crc16 => 16,
                CrcOptions.Crc17 => 17,
                CrcOptions.Crc21 => 21,
                CrcOptions.Crc24 => 24,
                CrcOptions.Crc30 => 30,
                CrcOptions.Crc31 => 31,
                CrcOptions.Crc32 => 32,
                CrcOptions.Crc40 => 40,
                CrcOptions.Crc64 => 64,
                CrcOptions.Crc82 => 82,
                _ => throw new InvalidOperationException(ExceptionMessages.InvalidOperationUnsupportedType)
            };
            var name = preset.ToString();
            return $"CRC{width}{(name == "Default" ? null : $"/{name.ToUpperInvariant()}")}";
        }

        private ICrcConfig<TValue> ValidateConfig(Enum preset)
        {
            preset ??= default(TValue) switch
            {
                byte => CrcOptions.Crc.Default,
                ushort => CrcOptions.Crc16.Default,
                uint => CrcOptions.Crc32.Default,
                ulong => CrcOptions.Crc64.Default,
                BigInteger => CrcOptions.Crc82.Default,
                _ => throw new InvalidOperationException(ExceptionMessages.InvalidOperationUnsupportedType)
            };
            object config = preset switch
            {
                CrcOptions.Crc x => CrcConfigManager.GetConfig(x),
                CrcOptions.Crc10 x => CrcConfigManager.GetConfig(x),
                CrcOptions.Crc11 x => CrcConfigManager.GetConfig(x),
                CrcOptions.Crc12 x => CrcConfigManager.GetConfig(x),
                CrcOptions.Crc13 x => CrcConfigManager.GetConfig(x),
                CrcOptions.Crc14 x => CrcConfigManager.GetConfig(x),
                CrcOptions.Crc15 x => CrcConfigManager.GetConfig(x),
                CrcOptions.Crc16 x => CrcConfigManager.GetConfig(x),
                CrcOptions.Crc17 x => CrcConfigManager.GetConfig(x),
                CrcOptions.Crc21 x => CrcConfigManager.GetConfig(x),
                CrcOptions.Crc24 x => CrcConfigManager.GetConfig(x),
                CrcOptions.Crc30 x => CrcConfigManager.GetConfig(x),
                CrcOptions.Crc31 x => CrcConfigManager.GetConfig(x),
                CrcOptions.Crc32 x => CrcConfigManager.GetConfig(x),
                CrcOptions.Crc40 x => CrcConfigManager.GetConfig(x),
                CrcOptions.Crc64 x => CrcConfigManager.GetConfig(x),
                CrcOptions.Crc82 x => CrcConfigManager.GetConfig(x),
                _ => throw new InvalidOperationException(ExceptionMessages.InvalidOperationUnsupportedType)
            };
            AlgorithmName = GetName(preset);
            return (ICrcConfig<TValue>)config;
        }
    }
}
