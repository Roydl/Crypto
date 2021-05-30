namespace Roydl.Crypto.Checksum
{
    using System;
    using System.IO;

    /// <summary>Provides functionality to compute CRC-32 hashes.</summary>
    public sealed class Crc32 : ChecksumAlgorithm<Crc32>
    {
        private static Memory<CrcConfig<uint>?> _configCache;
        private CrcConfig<uint> _current;
        private Crc32Preset _preset;

        /// <summary>Gets or sets a CRC-32 preset.</summary>
        public Crc32Preset Preset
        {
            get => _preset;
            set
            {
                _preset = value;
                if (_configCache.IsEmpty)
                    _configCache = new CrcConfig<uint>?[Enum.GetValues(typeof(Crc32Preset)).Length].AsMemory();
                ref var item = ref _configCache.Span[(int)value];
                item ??= CrcPreset.GetConfig(value);
                _current = item.Value;
            }
        }

        /// <summary>Initializes a new instance of the <see cref="Crc32"/> class.</summary>
        public Crc32(Crc32Preset preset = default) : base(32) =>
            Preset = preset;

        /// <summary>Initializes a new instance of the <see cref="Crc32"/> class and encrypts the specified stream.</summary>
        /// <inheritdoc cref="IChecksumAlgorithm.Encrypt(Stream)"/>
        public Crc32(Stream stream) : this() =>
            Encrypt(stream);

        /// <summary>Initializes a new instance of the <see cref="Crc32"/> class and encrypts the specified sequence of bytes.</summary>
        /// <inheritdoc cref="ChecksumAlgorithm(int, byte[])"/>
        public Crc32(byte[] bytes) : this() =>
            Encrypt(bytes);

        /// <summary>Initializes a new instance of the <see cref="Crc32"/> class and encrypts the specified text or file.</summary>
        /// <inheritdoc cref="ChecksumAlgorithm(int, string, bool)"/>
        public Crc32(string textOrFile, bool strIsFilePath) : this() =>
            Encrypt(textOrFile, strIsFilePath);

        /// <summary>Initializes a new instance of the <see cref="Crc32"/> class and encrypts the specified text.</summary>
        /// <inheritdoc cref="ChecksumAlgorithm(int, string)"/>
        public Crc32(string text) : this() =>
            Encrypt(text);

        /// <summary>Initializes a new instance of the <see cref="Crc32"/> class and encrypts the specified file.</summary>
        /// <inheritdoc cref="ChecksumAlgorithm(int, FileInfo)"/>
        public Crc32(FileInfo fileInfo) : this() =>
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
