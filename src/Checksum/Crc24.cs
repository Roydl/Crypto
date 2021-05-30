namespace Roydl.Crypto.Checksum
{
    using System;
    using System.IO;

    /// <summary>Provides functionality to compute CRC-24 hashes.</summary>
    public sealed class Crc24 : ChecksumAlgorithm<Crc24>
    {
        private static Memory<CrcConfig<uint>?> _configCache;
        private CrcConfig<uint> _current;
        private Crc24Preset _preset;

        /// <summary>Gets or sets a CRC-24 preset.</summary>
        public Crc24Preset Preset
        {
            get => _preset;
            set
            {
                _preset = value;
                if (_configCache.IsEmpty)
                    _configCache = new CrcConfig<uint>?[Enum.GetValues(typeof(Crc24Preset)).Length].AsMemory();
                ref var item = ref _configCache.Span[(int)value];
                item ??= CrcPreset.GetConfig(value);
                _current = item.Value;
            }
        }

        /// <summary>Initializes a new instance of the <see cref="Crc24"/> class.</summary>
        public Crc24(Crc24Preset preset = default) : base(24) =>
            Preset = preset;

        /// <summary>Initializes a new instance of the <see cref="Crc24"/> class and encrypts the specified stream.</summary>
        /// <inheritdoc cref="IChecksumAlgorithm.Encrypt(Stream)"/>
        public Crc24(Stream stream) : this() =>
            Encrypt(stream);

        /// <summary>Initializes a new instance of the <see cref="Crc24"/> class and encrypts the specified sequence of bytes.</summary>
        /// <inheritdoc cref="ChecksumAlgorithm(int, byte[])"/>
        public Crc24(byte[] bytes) : this() =>
            Encrypt(bytes);

        /// <summary>Initializes a new instance of the <see cref="Crc24"/> class and encrypts the specified text or file.</summary>
        /// <inheritdoc cref="ChecksumAlgorithm(int, string, bool)"/>
        public Crc24(string textOrFile, bool strIsFilePath) : this() =>
            Encrypt(textOrFile, strIsFilePath);

        /// <summary>Initializes a new instance of the <see cref="Crc24"/> class and encrypts the specified text.</summary>
        /// <inheritdoc cref="ChecksumAlgorithm(int, string)"/>
        public Crc24(string text) : this() =>
            Encrypt(text);

        /// <summary>Initializes a new instance of the <see cref="Crc24"/> class and encrypts the specified file.</summary>
        /// <inheritdoc cref="ChecksumAlgorithm(int, FileInfo)"/>
        public Crc24(FileInfo fileInfo) : this() =>
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
