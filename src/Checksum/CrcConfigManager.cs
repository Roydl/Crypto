namespace Roydl.Crypto.Checksum
{
    using System;
    using System.Collections.Concurrent;
    using System.Collections.Generic;
    using System.Linq;
    using System.Numerics;

    /// <summary>Provides static functions for loading preset <see cref="ICrcConfig{TValue}"/> structures.</summary>
    public static class CrcConfigManager
    {
        private static IDictionary<Enum, object> _cache;
        private static int _cacheCapacity, _cacheConcurrencyLevel;

        /// <summary>Gets or sets the initial number of CRC configurations that the storage can contain.</summary>
        /// <remarks>The capacity cannot be is less than <see cref="CacheConcurrencyLevel"/> or greater than <see cref="CacheCapacityLimit"/>; otherwise it is increased or decreased.</remarks>
        public static int CacheCapacity
        {
            get
            {
                if (_cacheCapacity == default)
                    CacheCapacity = (int)Math.Ceiling(CacheCapacityLimit / 3d);
                return _cacheCapacity;
            }
            set
            {
                var capacity = value;
                if (capacity < CacheConcurrencyLevel)
                    capacity = CacheConcurrencyLevel;
                if (capacity > CacheCapacityLimit)
                    capacity = CacheCapacityLimit;
                var reset = _cacheCapacity != default;
                _cacheCapacity = capacity;
                if (reset)
                    Cache = null;
            }
        }

        /// <summary>Gets the total number of CRC configurations available for storage.</summary>
        public static int CacheCapacityLimit { get; } =
            typeof(CrcOptions).GetNestedTypes().Where(t => t.IsEnum).Sum(t => Enum.GetValues(t).Length);

        /// <summary>Gets or sets the estimated number of threads that will update the storage concurrently.</summary>
        /// <remarks>If the number is less than 1, it is increased.</remarks>
        public static int CacheConcurrencyLevel
        {
            get
            {
                if (_cacheConcurrencyLevel == default)
                    CacheConcurrencyLevel = Environment.ProcessorCount;
                return _cacheConcurrencyLevel;
            }
            set
            {
                var level = value;
                if (level < 1)
                    level = 1;
                if (level > CacheCapacityLimit)
                    level = CacheCapacityLimit;
                var reset = _cacheConcurrencyLevel != default;
                _cacheConcurrencyLevel = level;
                if (reset)
                    Cache = null;
            }
        }

        /// <summary>Gets the number of CRC configurations currently stored.</summary>
        public static int CacheSize => Cache.Count;

        private static IDictionary<Enum, object> Cache
        {
            get
            {
                if (_cache == default)
                    Cache = default;
                return _cache;
            }
            set
            {
                if (value != default)
                {
                    _cache = value;
                    return;
                }
                var cache = new ConcurrentDictionary<Enum, object>(CacheConcurrencyLevel, CacheCapacity);
                if (_cache?.Count > 0)
                {
                    foreach (var (preset, config) in _cache)
                    {
                        if (cache.Count >= CacheCapacity)
                            break;
                        cache[preset] = config;
                    }
                    _cache.Clear();
                }
                _cache = cache;
            }
        }

        /// <summary>Removes all CRC configurations from internal storage.</summary>
        public static void ClearCache() =>
            Cache.Clear();

        /// <summary>Loads a predefined CRC-8 configuration structure.</summary>
        /// <param name="preset">The preset to be loaded.</param>
        /// <returns>A predefined CRC-8 configuration structure.</returns>
        /// <exception cref="ArgumentOutOfRangeException">preset is invalid.</exception>
        public static ICrcConfig<byte> GetConfig(CrcOptions.Crc preset)
        {
            if (GetCachedConfig<byte>(preset) is { } config)
                return config;
            config = preset switch
            {
                CrcOptions.Crc.Default =>
                    new CrcConfig(8, 0xf4, 0x07),

                CrcOptions.Crc.Autosar =>
                    new CrcConfig(8, 0xdf, 0x2f, 0xff, false, false, 0xff),

                CrcOptions.Crc.Bluetooth =>
                    new CrcConfig(8, 0x26, 0xe5, default, true, true),

                CrcOptions.Crc.Cdma2000 =>
                    new CrcConfig(8, 0xda, 0x9b, 0xff),

                CrcOptions.Crc.Darc =>
                    new CrcConfig(8, 0x15, 0x9c, default, true, true),

                CrcOptions.Crc.DvbS2 =>
                    new CrcConfig(8, 0xbc, 0xd5),

                CrcOptions.Crc.GsmA =>
                    new CrcConfig(8, 0x37, 0x1d),

                CrcOptions.Crc.GsmB =>
                    new CrcConfig(8, 0x94, 0x49, default, false, false, 0xff),

                CrcOptions.Crc.I4321 =>
                    new CrcConfig(8, 0xa1, 0x07, default, false, false, 0x55),

                CrcOptions.Crc.ICode =>
                    new CrcConfig(8, 0x7e, 0x1d, 0xfd),

                CrcOptions.Crc.Lte =>
                    new CrcConfig(8, 0xea, 0x9b),

                CrcOptions.Crc.Maxim =>
                    new CrcConfig(8, 0xa1, 0x8c, default, true, true),

                CrcOptions.Crc.MifareMad =>
                    new CrcConfig(8, 0x99, 0x1d, 0xc7),

                CrcOptions.Crc.Nrsc5 =>
                    new CrcConfig(8, 0xf7, 0x31, 0xff),

                CrcOptions.Crc.OpenSafety =>
                    new CrcConfig(8, 0x3e, 0x2f),

                CrcOptions.Crc.Rohc =>
                    new CrcConfig(8, 0xd0, 0xe0, 0xff, true, true),

                CrcOptions.Crc.SaeJ1850 =>
                    new CrcConfig(8, 0x4b, 0x1d, 0xff, false, false, 0xff),

                CrcOptions.Crc.Tech3250 =>
                    new CrcConfig(8, 0x97, 0xb8, 0xff, true, true),

                CrcOptions.Crc.Wcdma =>
                    new CrcConfig(8, 0x25, 0xd9, default, true, true),

                _ => throw new ArgumentOutOfRangeException(nameof(preset), preset, null)
            };
            UpdateConfigCache(preset, config);
            return config;
        }

        /// <summary>Loads a predefined CRC-10 configuration structure.</summary>
        /// <param name="preset">The preset to be loaded.</param>
        /// <returns>A predefined CRC-10 configuration structure.</returns>
        /// <exception cref="ArgumentOutOfRangeException">preset is invalid.</exception>
        public static ICrcConfig<ushort> GetConfig(CrcOptions.Crc10 preset)
        {
            if (GetCachedConfig<ushort>(preset) is { } config)
                return config;
            config = preset switch
            {
                CrcOptions.Crc10.Default =>
                    new CrcConfig16(10, 0x199, 0x233, default, false, false, default, 0x3ff),

                CrcOptions.Crc10.Cdma2000 =>
                    new CrcConfig16(10, 0x233, 0x3d9, 0x3ff, false, false, default, 0x3ff),

                CrcOptions.Crc10.Gsm =>
                    new CrcConfig16(10, 0x12a, 0x175, default, false, false, 0x3ff, 0x3ff),

                _ => throw new ArgumentOutOfRangeException(nameof(preset), preset, null)
            };
            UpdateConfigCache(preset, config);
            return config;
        }

        /// <summary>Loads a predefined CRC-11 configuration structure.</summary>
        /// <param name="preset">The preset to be loaded.</param>
        /// <returns>A predefined CRC-11 configuration structure.</returns>
        /// <exception cref="ArgumentOutOfRangeException">preset is invalid.</exception>
        public static ICrcConfig<ushort> GetConfig(CrcOptions.Crc11 preset)
        {
            if (GetCachedConfig<ushort>(preset) is { } config)
                return config;
            config = preset switch
            {
                CrcOptions.Crc11.Default =>
                    new CrcConfig16(11, 0x5a3, 0x385, 0x01a),

                CrcOptions.Crc11.Umts =>
                    new CrcConfig16(11, 0x061, 0x307, default, false, false, default, 0x7ff),

                _ => throw new ArgumentOutOfRangeException(nameof(preset), preset, null)
            };
            UpdateConfigCache(preset, config);
            return config;
        }

        /// <summary>Loads a predefined CRC-12 configuration structure.</summary>
        /// <param name="preset">The preset to be loaded.</param>
        /// <returns>A predefined CRC-12 configuration structure.</returns>
        /// <exception cref="ArgumentOutOfRangeException">preset is invalid.</exception>
        public static ICrcConfig<ushort> GetConfig(CrcOptions.Crc12 preset)
        {
            if (GetCachedConfig<ushort>(preset) is { } config)
                return config;
            config = preset switch
            {
                CrcOptions.Crc12.Default =>
                    new CrcConfig16(12, 0xd4d, 0xf13, 0xfff, false, false, default, 0xfff),

                CrcOptions.Crc12.Dect =>
                    new CrcConfig16(12, 0xf5b, 0x80f, default, false, false, default, 0xfff),

                CrcOptions.Crc12.Gsm =>
                    new CrcConfig16(12, 0xb34, 0xd31, default, false, false, 0xfff, 0xfff),

                CrcOptions.Crc12.Umts =>
                    new CrcConfig16(12, 0xdaf, 0x80f, default, false, true, default, 0xfff),

                _ => throw new ArgumentOutOfRangeException(nameof(preset), preset, null)
            };
            UpdateConfigCache(preset, config);
            return config;
        }

        /// <summary>Loads a predefined CRC-13 configuration structure.</summary>
        /// <param name="preset">The preset to be loaded.</param>
        /// <returns>A predefined CRC-13 configuration structure.</returns>
        /// <exception cref="ArgumentOutOfRangeException">preset is invalid.</exception>
        public static ICrcConfig<ushort> GetConfig(CrcOptions.Crc13 preset)
        {
            if (GetCachedConfig<ushort>(preset) is { } config)
                return config;
            config = preset switch
            {
                CrcOptions.Crc13.Default =>
                    new CrcConfig16(13, 0x04fa, 0x1cf5, default, false, false, default, 0x1fff),

                _ => throw new ArgumentOutOfRangeException(nameof(preset), preset, null)
            };
            UpdateConfigCache(preset, config);
            return config;
        }

        /// <summary>Loads a predefined CRC-14 configuration structure.</summary>
        /// <param name="preset">The preset to be loaded.</param>
        /// <returns>A predefined CRC-14 configuration structure.</returns>
        /// <exception cref="ArgumentOutOfRangeException">preset is invalid.</exception>
        public static ICrcConfig<ushort> GetConfig(CrcOptions.Crc14 preset)
        {
            if (GetCachedConfig<ushort>(preset) is { } config)
                return config;
            config = preset switch
            {
                CrcOptions.Crc14.Default =>
                    new CrcConfig16(14, 0x082d, 0x2804, default, true, true, default, 0x3fff),

                CrcOptions.Crc14.Gsm =>
                    new CrcConfig16(14, 0x30ae, 0x202d, default, false, false, 0x3fff, 0x3fff),

                _ => throw new ArgumentOutOfRangeException(nameof(preset), preset, null)
            };
            UpdateConfigCache(preset, config);
            return config;
        }

        /// <summary>Loads a predefined CRC-15 configuration structure.</summary>
        /// <param name="preset">The preset to be loaded.</param>
        /// <returns>A predefined CRC-15 configuration structure.</returns>
        /// <exception cref="ArgumentOutOfRangeException">preset is invalid.</exception>
        public static ICrcConfig<ushort> GetConfig(CrcOptions.Crc15 preset)
        {
            if (GetCachedConfig<ushort>(preset) is { } config)
                return config;
            config = preset switch
            {
                CrcOptions.Crc15.Default =>
                    new CrcConfig16(15, 0x059e, 0x4599),

                CrcOptions.Crc15.Mpt1327 =>
                    new CrcConfig16(15, 0x2566, 0x6815, default, false, false, 0x0001, 0x7fff),

                _ => throw new ArgumentOutOfRangeException(nameof(preset), preset, null)
            };
            UpdateConfigCache(preset, config);
            return config;
        }

        /// <summary>Loads a predefined CRC-16 configuration structure.</summary>
        /// <param name="preset">The preset to be loaded.</param>
        /// <returns>A predefined CRC-16 configuration structure.</returns>
        /// <exception cref="ArgumentOutOfRangeException">preset is invalid.</exception>
        public static ICrcConfig<ushort> GetConfig(CrcOptions.Crc16 preset)
        {
            if (GetCachedConfig<ushort>(preset) is { } config)
                return config;
            config = preset switch
            {
                CrcOptions.Crc16.Default =>
                    new CrcConfig16(16, 0xbb3d, 0xa001, default, true, true),

                CrcOptions.Crc16.A =>
                    new CrcConfig16(16, 0xbf05, 0x8408, 0x6363, true, true),

                CrcOptions.Crc16.Buypass =>
                    new CrcConfig16(16, 0xfee8, 0x8005),

                CrcOptions.Crc16.Cdma2000 =>
                    new CrcConfig16(16, 0x4c06, 0xc867, 0xffff),

                CrcOptions.Crc16.Cms =>
                    new CrcConfig16(16, 0xaee7, 0x8005, 0xffff),

                CrcOptions.Crc16.Dds110 =>
                    new CrcConfig16(16, 0x9ecf, 0x8005, 0x800d),

                CrcOptions.Crc16.DectR =>
                    new CrcConfig16(16, 0x007e, 0x0589, default, false, false, 0x0001),

                CrcOptions.Crc16.DectX =>
                    new CrcConfig16(16, 0x007f, 0x0589),

                CrcOptions.Crc16.Dnp =>
                    new CrcConfig16(16, 0xea82, 0xa6bc, default, true, true, 0xffff),

                CrcOptions.Crc16.En13757 =>
                    new CrcConfig16(16, 0xc2b7, 0x3d65, default, false, false, 0xffff),

                CrcOptions.Crc16.Genibus =>
                    new CrcConfig16(16, 0xd64e, 0x1021, 0xffff, false, false, 0xffff),

                CrcOptions.Crc16.Gsm =>
                    new CrcConfig16(16, 0xce3c, 0x1021, default, false, false, 0xffff),

                CrcOptions.Crc16.Ibm3740 =>
                    new CrcConfig16(16, 0x29b1, 0x1021, 0xffff),

                CrcOptions.Crc16.IbmSdlc =>
                    new CrcConfig16(16, 0x906e, 0x8408, 0xffff, true, true, 0xffff),

                CrcOptions.Crc16.Kermit =>
                    new CrcConfig16(16, 0x2189, 0x8408, default, true, true),

                CrcOptions.Crc16.Lj1200 =>
                    new CrcConfig16(16, 0xbdf4, 0x6f63),

                CrcOptions.Crc16.Maxim =>
                    new CrcConfig16(16, 0x44c2, 0xa001, default, true, true, 0xffff),

                CrcOptions.Crc16.Mcrf4Xx =>
                    new CrcConfig16(16, 0x6f91, 0x8408, 0xffff, true, true),

                CrcOptions.Crc16.ModBus =>
                    new CrcConfig16(16, 0x4b37, 0xa001, 0xffff, true, true),

                CrcOptions.Crc16.Riello =>
                    new CrcConfig16(16, 0x63d0, 0x8408, 0x554d, true, true),

                CrcOptions.Crc16.SpiFujitsu =>
                    new CrcConfig16(16, 0xe5cc, 0x1021, 0x1d0f),

                CrcOptions.Crc16.T10Dif =>
                    new CrcConfig16(16, 0xd0db, 0x8bb7),

                CrcOptions.Crc16.TeleDisk =>
                    new CrcConfig16(16, 0x0fb3, 0xa097),

                CrcOptions.Crc16.Tms37157 =>
                    new CrcConfig16(16, 0x26b1, 0x8408, 0x3791, true, true),

                CrcOptions.Crc16.Usb =>
                    new CrcConfig16(16, 0xb4c8, 0xa001, 0xffff, true, true, 0xffff),

                CrcOptions.Crc16.XModem =>
                    new CrcConfig16(16, 0x31c3, 0x1021),

                _ => throw new ArgumentOutOfRangeException(nameof(preset), preset, null)
            };
            UpdateConfigCache(preset, config);
            return config;
        }

        /// <summary>Loads a predefined CRC-17 configuration structure.</summary>
        /// <param name="preset">The preset to be loaded.</param>
        /// <returns>A predefined CRC-17 configuration structure.</returns>
        /// <exception cref="ArgumentOutOfRangeException">preset is invalid.</exception>
        public static ICrcConfig<uint> GetConfig(CrcOptions.Crc17 preset)
        {
            if (GetCachedConfig<uint>(preset) is { } config)
                return config;
            config = preset switch
            {
                CrcOptions.Crc17.Default =>
                    new CrcConfig32(17, 0x04f03u, 0x1685bu, default, false, false, default, 0x33ffffu),

                _ => throw new ArgumentOutOfRangeException(nameof(preset), preset, null)
            };
            UpdateConfigCache(preset, config);
            return config;
        }

        /// <summary>Loads a predefined CRC-21 configuration structure.</summary>
        /// <param name="preset">The preset to be loaded.</param>
        /// <returns>A predefined CRC-21 configuration structure.</returns>
        /// <exception cref="ArgumentOutOfRangeException">preset is invalid.</exception>
        public static ICrcConfig<uint> GetConfig(CrcOptions.Crc21 preset)
        {
            if (GetCachedConfig<uint>(preset) is { } config)
                return config;
            config = preset switch
            {
                CrcOptions.Crc21.Default =>
                    new CrcConfig32(21, 0x0ed841u, 0x102899u, default, false, false, default, 0x1fffffu),

                _ => throw new ArgumentOutOfRangeException(nameof(preset), preset, null)
            };
            UpdateConfigCache(preset, config);
            return config;
        }

        /// <summary>Loads a predefined CRC-24 configuration structure.</summary>
        /// <param name="preset">The preset to be loaded.</param>
        /// <returns>A predefined CRC-24 configuration structure.</returns>
        /// <exception cref="ArgumentOutOfRangeException">preset is invalid.</exception>
        public static ICrcConfig<uint> GetConfig(CrcOptions.Crc24 preset)
        {
            if (GetCachedConfig<uint>(preset) is { } config)
                return config;
            config = preset switch
            {
                CrcOptions.Crc24.Default =>
                    new CrcConfig32(24, 0x21cf02u, 0x864cfbu, 0xb704ceu),

                CrcOptions.Crc24.Ble =>
                    new CrcConfig32(24, 0xc25a56u, 0xda6000u, 0xaaaaaau, true, true),

                CrcOptions.Crc24.LteA =>
                    new CrcConfig32(24, 0xcde703u, 0x864cfbu),

                CrcOptions.Crc24.LteB =>
                    new CrcConfig32(24, 0x23ef52u, 0x800063u),

                CrcOptions.Crc24.FlexRayA =>
                    new CrcConfig32(24, 0x7979bdu, 0x5d6dcbu, 0xfedcbau),

                CrcOptions.Crc24.FlexRayB =>
                    new CrcConfig32(24, 0x1f23b8u, 0x5d6dcbu, 0xabcdefu),

                CrcOptions.Crc24.Interlaken =>
                    new CrcConfig32(24, 0xb4f3e6u, 0x328b63u, 0xffffffu, false, false, 0xffffffu),

                CrcOptions.Crc24.Os9 =>
                    new CrcConfig32(24, 0x200fa5u, 0x800063u, 0xffffffu, false, false, 0xffffffu),

                _ => throw new ArgumentOutOfRangeException(nameof(preset), preset, null)
            };
            UpdateConfigCache(preset, config);
            return config;
        }

        /// <summary>Loads a predefined CRC-30 configuration structure.</summary>
        /// <param name="preset">The preset to be loaded.</param>
        /// <returns>A predefined CRC-30 configuration structure.</returns>
        /// <exception cref="ArgumentOutOfRangeException">preset is invalid.</exception>
        public static ICrcConfig<uint> GetConfig(CrcOptions.Crc30 preset)
        {
            if (GetCachedConfig<uint>(preset) is { } config)
                return config;
            config = preset switch
            {
                CrcOptions.Crc30.Default =>
                    new CrcConfig32(30, 0x04c34abfu, 0x2030b9c7u, 0x3fffffffu, false, false, 0x3fffffffu, 0x3fffffffu),

                _ => throw new ArgumentOutOfRangeException(nameof(preset), preset, null)
            };
            UpdateConfigCache(preset, config);
            return config;
        }

        /// <summary>Loads a predefined CRC-31 configuration structure.</summary>
        /// <param name="preset">The preset to be loaded.</param>
        /// <returns>A predefined CRC-31 configuration structure.</returns>
        /// <exception cref="ArgumentOutOfRangeException">preset is invalid.</exception>
        public static ICrcConfig<uint> GetConfig(CrcOptions.Crc31 preset)
        {
            if (GetCachedConfig<uint>(preset) is { } config)
                return config;
            config = preset switch
            {
                CrcOptions.Crc31.Default =>
                    new CrcConfig32(31, 0x0ce9e46cu, 0x4c11db7u, 0x7fffffffu, false, false, 0x7fffffffu, 0x7fffffffu),

                _ => throw new ArgumentOutOfRangeException(nameof(preset), preset, null)
            };
            UpdateConfigCache(preset, config);
            return config;
        }

        /// <summary>Loads a predefined CRC-32 configuration structure.</summary>
        /// <param name="preset">The preset to be loaded.</param>
        /// <returns>A predefined CRC-32 configuration structure.</returns>
        /// <exception cref="ArgumentOutOfRangeException">preset is invalid.</exception>
        public static ICrcConfig<uint> GetConfig(CrcOptions.Crc32 preset)
        {
            if (GetCachedConfig<uint>(preset) is { } config)
                return config;
            config = preset switch
            {
                CrcOptions.Crc32.Default =>
                    new CrcConfig32(32, 0xcbf43926u, 0xedb88320u, 0xffffffffu, true, true, 0xffffffffu),

                CrcOptions.Crc32.Autosar =>
                    new CrcConfig32(32, 0x1697d06au, 0xc8df352fu, 0xffffffffu, true, true, 0xffffffffu),

                CrcOptions.Crc32.CdRomEdc =>
                    new CrcConfig32(32, 0x6ec2edc4u, 0xd8018001u, default, true, true),

                CrcOptions.Crc32.Q =>
                    new CrcConfig32(32, 0x3010bf7fu, 0x814141abu),

                CrcOptions.Crc32.BZip2 =>
                    new CrcConfig32(32, 0xfc891918u, 0x04c11db7u, 0xffffffffu, false, false, 0xffffffffu),

                CrcOptions.Crc32.C =>
                    new CrcConfig32(32, 0xe3069283u, 0x82f63b78u, 0xffffffffu, true, true, 0xffffffffu),

                CrcOptions.Crc32.D =>
                    new CrcConfig32(32, 0x87315576u, 0xd419cc15u, 0xffffffffu, true, true, 0xffffffffu),

                CrcOptions.Crc32.JamCrc =>
                    new CrcConfig32(32, 0x340bc6d9u, 0xedb88320u, 0xffffffffu, true, true),

                CrcOptions.Crc32.Mpeg2 =>
                    new CrcConfig32(32, 0x0376e6e7u, 0x04c11db7u, 0xffffffffu),

                CrcOptions.Crc32.Posix =>
                    new CrcConfig32(32, 0x765e7680u, 0x04c11db7u, default, false, false, 0xffffffffu),

                CrcOptions.Crc32.Xfer =>
                    new CrcConfig32(32, 0xbd0be338u, 0x000000afu),

                _ => throw new ArgumentOutOfRangeException(nameof(preset), preset, null)
            };
            UpdateConfigCache(preset, config);
            return config;
        }

        /// <summary>Loads a predefined CRC-40 configuration structure.</summary>
        /// <param name="preset">The preset to be loaded.</param>
        /// <returns>A predefined CRC-40 configuration structure.</returns>
        /// <exception cref="ArgumentOutOfRangeException">preset is invalid.</exception>
        public static ICrcConfig<ulong> GetConfig(CrcOptions.Crc40 preset)
        {
            if (GetCachedConfig<ulong>(preset) is { } config)
                return config;
            config = preset switch
            {
                CrcOptions.Crc40.Default =>
                    new CrcConfig64(40, 0xd4164fc646uL, 0x0004820009uL, default, false, false, 0xffffffffffuL),

                _ => throw new ArgumentOutOfRangeException(nameof(preset), preset, null)
            };
            UpdateConfigCache(preset, config);
            return config;
        }

        /// <summary>Loads a predefined CRC-64 configuration structure.</summary>
        /// <param name="preset">The preset to be loaded.</param>
        /// <returns>A predefined CRC-64 configuration structure.</returns>
        /// <exception cref="ArgumentOutOfRangeException">preset is invalid.</exception>
        public static ICrcConfig<ulong> GetConfig(CrcOptions.Crc64 preset)
        {
            if (GetCachedConfig<ulong>(preset) is { } config)
                return config;
            config = preset switch
            {
                CrcOptions.Crc64.Default =>
                    new CrcConfig64(64, 0x6c40df5f0b497347uL, 0x42f0e1eba9ea3693uL),

                CrcOptions.Crc64.We =>
                    new CrcConfig64(64, 0x62ec59e3f1a4f00auL, 0x42f0e1eba9ea3693uL, 0xffffffffffffffffuL, false, false, 0xffffffffffffffffuL),

                CrcOptions.Crc64.Xz =>
                    new CrcConfig64(64, 0x995dc9bbdf1939fauL, 0xc96c5795d7870f42uL, 0xffffffffffffffffuL, true, true, 0xffffffffffffffffuL),

                CrcOptions.Crc64.GoIso =>
                    new CrcConfig64(64, 0xb90956c775a41001uL, 0xd800000000000000uL, 0xffffffffffffffffuL, true, true, 0xffffffffffffffffuL),

                _ => throw new ArgumentOutOfRangeException(nameof(preset), preset, null)
            };
            UpdateConfigCache(preset, config);
            return config;
        }

        /// <summary>Loads a predefined CRC-82 configuration structure.</summary>
        /// <param name="preset">The preset to be loaded.</param>
        /// <returns>A predefined CRC-82 configuration structure.</returns>
        /// <exception cref="ArgumentOutOfRangeException">preset is invalid.</exception>
        public static ICrcConfig<BigInteger> GetConfig(CrcOptions.Crc82 preset)
        {
            if (GetCachedConfig<BigInteger>(preset) is { } config)
                return config;
            config = preset switch
            {
                CrcOptions.Crc82.Default =>
                    new CrcConfigBeyond(82, "0x09ea83f625023801fd612", "0x220808a00a2022200c430", default, true, true, default, "0x3ffffffffffffffffffff"),

                _ => throw new ArgumentOutOfRangeException(nameof(preset), preset, null)
            };
            UpdateConfigCache(preset, config);
            return config;
        }

        private static ICrcConfig<TValue> GetCachedConfig<TValue>(Enum preset) where TValue : struct, IComparable, IFormattable
        {
            if (Cache.TryGetValue(preset, out var config))
                return (ICrcConfig<TValue>)config;
            return null;
        }

        private static void UpdateConfigCache<TValue>(Enum preset, ICrcConfig<TValue> config) where TValue : struct, IComparable, IFormattable
        {
            if (Cache.Count >= CacheCapacity)
                Cache.Clear();
            Cache[preset] = config;
        }
    }
}
