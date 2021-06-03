namespace Roydl.Crypto.Checksum
{
    using System;
    using System.IO;

    /// <summary>Provides functionality to compute CRC-64 hashes.</summary>
    public sealed class Crc64 : ChecksumAlgorithm<Crc64, ulong>
    {
        private static Memory<ICrcConfig<ulong>> _configCache;
        private ICrcConfig<ulong> _current;
        private Crc64Preset _preset;

        /// <summary>Gets or sets a CRC-64 preset.</summary>
        public Crc64Preset Preset
        {
            get => _preset;
            set
            {
                if (_preset != value)
                    Reset();
                _preset = value;
                if (_configCache.IsEmpty)
                    _configCache = new ICrcConfig<ulong>[Enum.GetValues(typeof(Crc64Preset)).Length].AsMemory();
                ref var item = ref _configCache.Span[(int)value];
                item ??= CrcPreset.GetConfig(value);
                _current = item;
            }
        }

        /// <summary>Initializes a new instance of the <see cref="Crc64"/> class.</summary>
        public Crc64(Crc64Preset preset = default) : base(64) =>
            Preset = preset;

        /// <summary>Initializes a new instance of the <see cref="Crc64"/> class and encrypts the specified stream.</summary>
        /// <inheritdoc cref="IChecksumAlgorithm.Encrypt(Stream)"/>
        public Crc64(Stream stream) : this() =>
            Encrypt(stream);

        /// <summary>Initializes a new instance of the <see cref="Crc64"/> class and encrypts the specified sequence of bytes.</summary>
        /// <inheritdoc cref="ChecksumAlgorithm(int, byte[])"/>
        public Crc64(byte[] bytes) : this() =>
            Encrypt(bytes);

        /// <summary>Initializes a new instance of the <see cref="Crc64"/> class and encrypts the specified text or file.</summary>
        /// <inheritdoc cref="ChecksumAlgorithm(int, string, bool)"/>
        public Crc64(string textOrFile, bool strIsFilePath) : this() =>
            Encrypt(textOrFile, strIsFilePath);

        /// <summary>Initializes a new instance of the <see cref="Crc64"/> class and encrypts the specified text.</summary>
        /// <inheritdoc cref="ChecksumAlgorithm(int, string)"/>
        public Crc64(string text) : this() =>
            Encrypt(text);

        /// <summary>Initializes a new instance of the <see cref="Crc64"/> class and encrypts the specified file.</summary>
        /// <inheritdoc cref="ChecksumAlgorithm(int, FileInfo)"/>
        public Crc64(FileInfo fileInfo) : this() =>
            Encrypt(fileInfo);

        /// <inheritdoc/>
        public override void Encrypt(Stream stream)
        {
            Reset();
            if (stream == null)
                throw new ArgumentNullException(nameof(stream));
            _current.ComputeHash(stream, out var num);
            HashNumber = num;
            RawHash = CryptoUtils.GetByteArray(num, RawHashSize);
        }
    }
}
