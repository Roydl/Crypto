namespace Roydl.Crypto.Checksum
{
    using System;
    using System.IO;

    /// <summary>Provides functionality to compute CRC-16 hashes.</summary>
    public sealed class Crc16 : ChecksumAlgorithm<Crc16>
    {
        private static Memory<CrcConfig<ushort>?> _configCache;
        private CrcConfig<ushort> _current;
        private Crc16Preset _preset;

        /// <summary>Gets or sets a CRC-16 preset.</summary>
        public Crc16Preset Preset
        {
            get => _preset;
            set
            {
                _preset = value;
                if (_configCache.IsEmpty)
                    _configCache = new CrcConfig<ushort>?[Enum.GetValues(typeof(Crc16Preset)).Length].AsMemory();
                ref var item = ref _configCache.Span[(int)value];
                item ??= CrcPreset.GetConfig(value);
                _current = item.Value;
            }
        }

        /// <summary>Initializes a new instance of the <see cref="Crc16"/> class.</summary>
        public Crc16(Crc16Preset preset = default) : base(16) =>
            Preset = preset;

        /// <summary>Initializes a new instance of the <see cref="Crc16"/> class and encrypts the specified stream.</summary>
        /// <inheritdoc cref="IChecksumAlgorithm.Encrypt(Stream)"/>
        public Crc16(Stream stream) : this() =>
            Encrypt(stream);

        /// <summary>Initializes a new instance of the <see cref="Crc16"/> class and encrypts the specified sequence of bytes.</summary>
        /// <inheritdoc cref="ChecksumAlgorithm(int, byte[])"/>
        public Crc16(byte[] bytes) : this() =>
            Encrypt(bytes);

        /// <summary>Initializes a new instance of the <see cref="Crc16"/> class and encrypts the specified text or file.</summary>
        /// <inheritdoc cref="ChecksumAlgorithm(int, string, bool)"/>
        public Crc16(string textOrFile, bool strIsFilePath) : this() =>
            Encrypt(textOrFile, strIsFilePath);

        /// <summary>Initializes a new instance of the <see cref="Crc16"/> class and encrypts the specified text.</summary>
        /// <inheritdoc cref="ChecksumAlgorithm(int, string)"/>
        public Crc16(string text) : this() =>
            Encrypt(text);

        /// <summary>Initializes a new instance of the <see cref="Crc16"/> class and encrypts the specified file.</summary>
        /// <inheritdoc cref="ChecksumAlgorithm(int, FileInfo)"/>
        public Crc16(FileInfo fileInfo) : this() =>
            Encrypt(fileInfo);

        /// <inheritdoc/>
        public override void Encrypt(Stream stream)
        {
            if (stream == null)
                throw new ArgumentNullException(nameof(stream));
            _current.ComputeHash(stream, out var num);
            HashNumber = num;
            RawHash = CryptoUtils.GetByteArray(num, RawHashSize);
        }
    }
}
